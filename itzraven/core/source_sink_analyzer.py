"""
White-box Depth: Source-Sink Taint Analyzer.

Shannon-inspired: traces tainted data from sources (user input, request params,
file reads, env vars) to sinks (SQL queries, eval, exec, shell, file write)
to find exploitable code paths without false positives.

Supports Python and JavaScript/TypeScript source analysis.
"""

import ast
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger

logger = get_logger()


# =========================================================================
# Taint Sources — places where attacker-controlled data enters the app
# =========================================================================
PYTHON_SOURCES: Dict[str, List[str]] = {
    "http_request": [
        "request.get", "request.form", "request.args", "request.json",
        "request.data", "request.cookies", "request.headers",
        "request.files", "request.values", "request.query_string",
        "request.url", "request.path", "request.referrer",
        "flask.request", "fastapi.Request",
        "self.request", "HttpRequest",
    ],
    "cli_input": [
        "sys.argv", "input()", "raw_input()",
        "argparse.", "click.argument", "click.option",
        "os.environ", "os.getenv", "environ.get",
    ],
    "file_read": [
        "open(", "Path.read_text", "Path.read_bytes",
        "file.read", "readlines", "readline",
    ],
    "database": [
        "cursor.fetch", "row.get", "result.", "record.",
    ],
    "graphql": [
        "context.user_input", "info.variable_values",
        "args.", "parent.",
    ],
}

JS_SOURCES: Dict[str, List[str]] = {
    "http_request": [
        "req.query", "req.params", "req.body", "req.headers",
        "req.cookies", "req.url", "req.path",
        "request.query", "request.params", "request.body",
        "ctx.query", "ctx.params", "ctx.request.body",
        "event.queryStringParameters", "event.body",
        "nextUrl.searchParams",
    ],
    "cli_input": [
        "process.argv", "process.env",
        "Deno.env", "Deno.args",
    ],
    "file_read": [
        "fs.readFile", "fs.readFileSync",
        "Deno.readTextFile",
    ],
}

# =========================================================================
# Taint Sinks — dangerous operations that should not receive tainted data
# =========================================================================
PYTHON_SINKS: Dict[str, List[str]] = {
    "sql_execution": [
        "cursor.execute", "db.execute", "db.run",
        "session.execute", "connection.execute",
        "executescript", "executemany",
        "raw_query", "db.query",
        "Model.query.filter", "Model.query.",
        ".filter(", ".where(",
    ],
    "shell_command": [
        "os.system", "os.popen", "subprocess.run",
        "subprocess.Popen", "subprocess.call",
        "subprocess.check_output", "subprocess.check_call",
        "commands.getstatusoutput", "commands.getoutput",
        "pexpect.run", "pexpect.spawn",
        "shlex.split",  # when source is used with subprocess
    ],
    "code_eval": [
        "eval(", "exec(", "compile(",
        "execfile", "ast.literal_eval",
        "__import__(", "importlib.import_module",
        "pickle.loads", "pickle.load",
        "yaml.load(",  # unsafe yaml load
        "marshal.load", "shelve.open",
    ],
    "file_write": [
        "open(", "Path.write_text", "Path.write_bytes",
        "file.write", "writelines",
        "os.write", "os.mkdir", "os.makedirs",
    ],
    "template_injection": [
        "render_template_string", "render_template",
        "jinja2.Template(", "Template(",
        ".render(", ".render_to_string",
    ],
    "path_traversal": [
        "Path(", "open(", "os.path.join",
        "send_file", "send_from_directory",
    ],
    "command_injection_extended": [
        "paramiko.SSHClient.exec_command",
        "fabric.run", "invoke.run",
        "docker.from_env", "docker.Client",
        "kubernetes.client",
    ],
    "nosql_injection": [
        "collection.find", "collection.find_one",
        "db.collection(", ".aggregate(",
        "mongo.db.", "pymongo.",
    ],
}

JS_SINKS: Dict[str, List[str]] = {
    "sql_execution": [
        "db.query", "db.execute", "connection.query",
        "prisma.", "knex.", "sequelize.",
        "TypeORM.", "entity.findOne", "entity.find",
        ".$where(",  # MongoDB
    ],
    "shell_command": [
        "exec(", "execSync(", "spawn(", "spawnSync(",
        "fork(", "child_process.",
        "Deno.run",
    ],
    "code_eval": [
        "eval(", "new Function(",
        "setTimeout(", "setInterval(",
    ],
    "file_write": [
        "fs.writeFile", "fs.writeFileSync",
        "fs.appendFile", "fs.appendFileSync",
        "Deno.writeTextFile",
    ],
}


@dataclass
class SourceSinkTrace:
    source_file: str
    source_type: str
    source_match: str
    source_line: int
    sink_type: str
    sink_match: str
    sink_line: int
    sanitized: bool = False
    confidence: float = 0.0

    def to_finding_dict(self, target: str = "") -> dict:
        return {
            "title": f"Unsafe data flow: {self.source_type} → {self.sink_type}",
            "description": (
                f"Tainted data from {self.source_type} ({self.source_match}) "
                f"at {self.source_file}:{self.source_line} flows to "
                f"{self.sink_type} ({self.sink_match}) at "
                f"{self.source_file}:{self.sink_line} without sanitization."
            ),
            "severity": "high" if self.confidence > 0.7 else "medium",
            "category": f"source_sink.{self.sink_type}",
            "evidence": f"{self.source_file}:{self.source_line} → {self.sink_line}",
            "remediation": (
                f"Sanitize tainted data before it reaches {self.sink_type}. "
                f"Use parameterized queries, input validation, or context-aware escaping."
            ),
            "file_path": self.source_file,
            "line_number": self.sink_line,
            "confidence": self.confidence,
            "validation_status": "unvalidated",
        }


class SourceSinkAnalyzer:
    """Scans source code for tainted data flows from sources to sinks."""

    def __init__(self, scan_path: Optional[str] = None):
        self._scan_path = Path(scan_path) if scan_path else Path.cwd()
        self._traces: List[SourceSinkTrace] = []

    def scan(self, path: Optional[str] = None) -> List[SourceSinkTrace]:
        target = Path(path) if path else self._scan_path
        self._traces.clear()

        if target.is_file():
            self._analyze_file(target)
        else:
            for ext in ("*.py", "*.js", "*.ts", "*.jsx", "*.tsx"):
                for f in sorted(target.rglob(ext)):
                    try:
                        self._analyze_file(f)
                    except Exception as e:
                        logger.debug(f"Skipping {f}: {e}")

        return self._traces

    def _analyze_file(self, filepath: Path) -> None:
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        lang = "python" if filepath.suffix == ".py" else "javascript"
        sources = PYTHON_SOURCES if lang == "python" else JS_SOURCES
        sinks = PYTHON_SINKS if lang == "python" else JS_SINKS

        file_sources = self._find_matches(content, sources)
        file_sinks = self._find_matches(content, sinks)

        if not file_sources or not file_sinks:
            return

        rel_path = str(filepath.relative_to(self._scan_path))
        self._trace_flows(rel_path, content, file_sources, file_sinks)

    def _find_matches(
        self, content: str, patterns: Dict[str, List[str]]
    ) -> List[Tuple[str, str, int]]:
        matches: List[Tuple[str, str, int]] = []
        for category, keywords in patterns.items():
            for kw in keywords:
                escaped = re.escape(kw)
                for m in re.finditer(escaped, content, re.IGNORECASE):
                    line = content[: m.start()].count("\n") + 1
                    matches.append((category, kw, line))
        return matches

    def _trace_flows(
        self,
        rel_path: str,
        content: str,
        sources: List[Tuple[str, str, int]],
        sinks: List[Tuple[str, str, int]],
    ) -> None:
        lines = content.split("\n")

        for src_cat, src_match, src_line in sources:
            for sink_cat, sink_match, sink_line in sinks:
                if sink_line < src_line:
                    continue

                sanitized = self._check_sanitization(lines, src_line, sink_line, rel_path)
                distance = sink_line - src_line
                base_conf = 0.85 if not sanitized else 0.25

                # Higher confidence when closer together (same function)
                confidence = base_conf * max(0.5, 1.0 - (distance / 200))
                confidence = min(1.0, max(0.1, confidence))

                trace = SourceSinkTrace(
                    source_file=rel_path,
                    source_type=src_cat,
                    source_match=src_match,
                    source_line=src_line,
                    sink_type=sink_cat,
                    sink_match=sink_match,
                    sink_line=sink_line,
                    sanitized=sanitized,
                    confidence=confidence,
                )
                self._traces.append(trace)

    def _check_sanitization(
        self, lines: List[str], src_line: int, sink_line: int, rel_path: str
    ) -> bool:
        context = lines[max(0, src_line - 1): min(len(lines), sink_line + 1)]
        context_text = "\n".join(context).lower()

        sanitizers = [
            "escape", "sanitize", "validate", "strip_tags",
            "html.escape", "cgi.escape",
            "parameterized", "prepared statement",
            "bind_param", "placeholder",
            "validators.", "schema.", "pydantic",
            "isinstance", "int(", "float(",
            "re.match", "re.search", "re.fullmatch",
            "dedent", "shlex.quote", "pipes.quote",
            "purify", "DOMPurify",
            "validator.", "sanitize-html",
            "helmet.", "csurf",
            "Joi.", "yup.", "zod.",
            "strip(", "replace(",
        ]
        return any(s in context_text for s in sanitizers)

    def get_traces(self) -> List[SourceSinkTrace]:
        return self._traces

    def get_unsanitized_traces(self, min_confidence: float = 0.5) -> List[SourceSinkTrace]:
        return [t for t in self._traces if not t.sanitized and t.confidence >= min_confidence]


_analyzer_instance: Optional[SourceSinkAnalyzer] = None


def get_source_sink_analyzer(scan_path: Optional[str] = None) -> SourceSinkAnalyzer:
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = SourceSinkAnalyzer(scan_path=scan_path)
    return _analyzer_instance

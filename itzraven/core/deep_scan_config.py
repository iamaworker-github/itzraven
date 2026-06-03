"""
Deep+Slow+Accurate Mode — Shannon's "quality over quantity" approach.

When active:
  - More payloads per test vector (3x-5x payload dictionaries)
  - Longer timeouts per request (5x-10x normal)
  - Recursive parameter discovery
  - Exhaustive header/parameter fuzzing
  - PoC verification on ALL findings before reporting (not just critical/high)
  - Source code analysis guides exploitation (white-box depth)
  - Multiple evasion techniques attempted per vector
  - Cross-agent correlation for attack chain validation

Configuration is used by the orchestrator to adjust agent behavior.
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class DeepScanConfig:
    """Configuration presets for Deep+Slow+Accurate mode."""

    # Multipliers relative to standard scan
    payload_multiplier: float = 3.0
    timeout_multiplier: float = 5.0
    max_recursion_depth: int = 3
    max_payloads_per_vector: int = 50

    # Exhaustive options
    fuzz_headers: bool = True
    fuzz_parameters: bool = True
    fuzz_cookies: bool = True
    fuzz_methods: bool = True
    fuzz_content_types: bool = True

    # Evasion techniques to try
    evasion_techniques: tuple = (
        "none",
        "url_encoding",
        "double_url_encoding",
        "unicode_normalization",
        "case_switching",
        "null_byte",
        "parameter_pollution",
        "chunked_encoding",
        "multipart_mixed",
        "charset_bypass",
    )

    # White-box depth
    enable_source_sink_analysis: bool = True
    enable_call_graph_tracing: bool = True

    # Verification
    require_poc_for_all: bool = True
    validate_poc_in_sandbox: bool = True
    poc_retry_count: int = 3

    # Cross-agent correlation
    correlate_across_agents: bool = True
    build_attack_chains: bool = True
    max_chain_depth: int = 4

    # Resource limits
    max_concurrent_requests: int = 3  # Slower = fewer concurrent
    request_delay: float = 0.5  # Delay between requests
    max_scan_time_hours: float = 4.0

    # Reporting
    include_all_attempts: bool = False  # Only report confirmed vulns
    include_negative_results: bool = False
    generate_attack_graph: bool = True
    generate_reproduction_script: bool = True

    @classmethod
    def quick(cls) -> "DeepScanConfig":
        return cls(
            payload_multiplier=0.5,
            timeout_multiplier=1.0,
            max_recursion_depth=0,
            max_payloads_per_vector=5,
            fuzz_headers=False,
            fuzz_parameters=False,
            fuzz_cookies=False,
            fuzz_methods=False,
            fuzz_content_types=False,
            evasion_techniques=("none",),
            enable_source_sink_analysis=False,
            enable_call_graph_tracing=False,
            require_poc_for_all=False,
            validate_poc_in_sandbox=False,
            correlate_across_agents=False,
            build_attack_chains=False,
            max_concurrent_requests=10,
            request_delay=0.0,
            max_scan_time_hours=0.25,
            include_all_attempts=True,
            include_negative_results=False,
            generate_attack_graph=False,
            generate_reproduction_script=False,
        )

    @classmethod
    def standard(cls) -> "DeepScanConfig":
        return cls()

    @classmethod
    def deep(cls) -> "DeepScanConfig":
        return cls(
            payload_multiplier=5.0,
            timeout_multiplier=10.0,
            max_recursion_depth=5,
            max_payloads_per_vector=200,
            evasion_techniques=(
                "none",
                "url_encoding",
                "double_url_encoding",
                "unicode_normalization",
                "case_switching",
                "null_byte",
                "parameter_pollution",
                "chunked_encoding",
                "multipart_mixed",
                "charset_bypass",
                "base64_encoding",
                "hex_encoding",
                "utf7",
                "utf16",
                "mutation_xss",
                "polyglot",
            ),
            max_concurrent_requests=1,
            request_delay=2.0,
            max_scan_time_hours=8.0,
            generate_attack_graph=True,
            generate_reproduction_script=True,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload_multiplier": self.payload_multiplier,
            "timeout_multiplier": self.timeout_multiplier,
            "max_recursion_depth": self.max_recursion_depth,
            "max_payloads_per_vector": self.max_payloads_per_vector,
            "fuzz_headers": self.fuzz_headers,
            "fuzz_parameters": self.fuzz_parameters,
            "fuzz_cookies": self.fuzz_cookies,
            "fuzz_methods": self.fuzz_methods,
            "fuzz_content_types": self.fuzz_content_types,
            "evasion_techniques": list(self.evasion_techniques),
            "enable_source_sink_analysis": self.enable_source_sink_analysis,
            "enable_call_graph_tracing": self.enable_call_graph_tracing,
            "require_poc_for_all": self.require_poc_for_all,
            "validate_poc_in_sandbox": self.validate_poc_in_sandbox,
            "poc_retry_count": self.poc_retry_count,
            "correlate_across_agents": self.correlate_across_agents,
            "build_attack_chains": self.build_attack_chains,
            "max_chain_depth": self.max_chain_depth,
            "max_concurrent_requests": self.max_concurrent_requests,
            "request_delay": self.request_delay,
            "max_scan_time_hours": self.max_scan_time_hours,
            "include_all_attempts": self.include_all_attempts,
            "include_negative_results": self.include_negative_results,
            "generate_attack_graph": self.generate_attack_graph,
            "generate_reproduction_script": self.generate_reproduction_script,
        }

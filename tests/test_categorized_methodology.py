"""Tests for the categorized methodology system (OSINT/Pentest/CTF)."""

from itzraven.knowledge.categorized_methodology import (
    OSINT_METHODOLOGIES, PENTEST_METHODOLOGIES, CTF_METHODOLOGIES,
    MANDATORY_DATASETS, ALL_CATEGORIZED, get_methodology,
    search_methodology, list_all_tools, Category, MethodologyNode,
)


def test_osint_methodology_exists():
    assert OSINT_METHODOLOGIES is not None
    assert OSINT_METHODOLOGIES.category == Category.OSINT
    assert len(OSINT_METHODOLOGIES.sub_nodes) >= 7


def test_pentest_methodology_exists():
    assert PENTEST_METHODOLOGIES is not None
    assert PENTEST_METHODOLOGIES.category == Category.PENTEST
    assert len(PENTEST_METHODOLOGIES.sub_nodes) >= 5


def test_ctf_methodology_exists():
    assert CTF_METHODOLOGIES is not None
    assert CTF_METHODOLOGIES.category == Category.CTF
    assert len(CTF_METHODOLOGIES.sub_nodes) >= 5


def test_mandatory_datasets():
    required = ["breach_corpuses", "whois_history", "dns_history", "social_metadata",
                "exif_datasets", "github_leaks", "paste_sites", "archived_urls",
                "map_geolocation_datasets"]
    for dataset in required:
        assert dataset in MANDATORY_DATASETS, f"Missing dataset: {dataset}"
        assert "sources" in MANDATORY_DATASETS[dataset]
        assert "techniques" in MANDATORY_DATASETS[dataset]
        assert len(MANDATORY_DATASETS[dataset]["sources"]) >= 2


def test_all_categorized():
    for cat in ["osint", "pentest", "ctf", "datasets"]:
        assert cat in ALL_CATEGORIZED


def test_get_methodology():
    osint = get_methodology("osint")
    assert osint is not None
    assert osint.name == "OSINT Methodology"


def test_search_methodology():
    results = search_methodology("SQL")
    assert len(results) >= 1

    results = search_methodology("Sherlock")
    assert len(results) >= 1


def test_search_by_category():
    results = search_methodology("XSS", category="pentest")
    for r in results:
        assert r.get("category") == "pentest" or r.get("category") is None


def test_list_all_tools():
    tools = list_all_tools()
    assert "osint" in tools
    assert "pentest" in tools
    assert "ctf" in tools
    assert len(tools["osint"]) > 10
    assert len(tools["pentest"]) > 10


def test_methodology_node_creation():
    node = MethodologyNode(
        name="Test Node",
        category=Category.OSINT,
        source="Test",
        tools=["tool1", "tool2"],
        techniques=["tech1"],
        commands=["cmd1"],
    )
    assert node.name == "Test Node"
    assert len(node.tools) == 2
    d = node.to_dict()
    assert d["name"] == "Test Node"
    assert d["category"] == "osint"


def test_node_with_subnodes():
    parent = MethodologyNode(
        name="Parent",
        category=Category.PENTEST,
        source="Test",
        sub_nodes=[
            MethodologyNode(name="Child", category=Category.PENTEST, source="Test"),
        ],
    )
    assert len(parent.sub_nodes) == 1
    assert parent.sub_nodes[0].name == "Child"


def test_github_leak_patterns():
    patterns = MANDATORY_DATASETS["github_leaks"]["patterns"]
    assert "aws_key" in patterns
    assert "github_token" in patterns
    assert "private_key" in patterns
    assert len(patterns) >= 6


def test_breach_corpus_sources():
    sources = MANDATORY_DATASETS["breach_corpuses"]["sources"]
    assert "HaveIBeenPwned API" in sources[0] or "DeHashed" in sources


def test_methodology_commands_exist():
    """Ensure OSINT methodology has actual command examples."""
    has_commands = False

    def check_commands(node):
        nonlocal has_commands
        if node.commands:
            has_commands = True
        for sub in node.sub_nodes:
            check_commands(sub)

    check_commands(PENTEST_METHODOLOGIES)
    assert has_commands


def test_methodology_bypasses_exist():
    """Ensure pentest methodology has bypass techniques."""
    sqli = None
    for sub in PENTEST_METHODOLOGIES.sub_nodes:
        if sub.name == "Web Application Pentesting":
            for s in sub.sub_nodes:
                if s.name == "SQL Injection":
                    sqli = s
                    break
    assert sqli is not None
    assert len(sqli.bypasses) >= 3

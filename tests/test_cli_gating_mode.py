from itzraven.cli import build_parser


def test_scan_parser_defaults_gating_mode_to_shadow():
    parser = build_parser()
    args = parser.parse_args(["scan", "https://example.com"])

    assert args.gating_mode == "shadow"


def test_scan_parser_accepts_enforced_gating_mode():
    parser = build_parser()
    args = parser.parse_args(["scan", "https://example.com", "--gating-mode", "enforced"])

    assert args.gating_mode == "enforced"

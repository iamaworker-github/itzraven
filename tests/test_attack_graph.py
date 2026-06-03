"""Tests for Attack Graph Visualization."""

from itzraven.ui.attack_graph import AttackGraphVisualizer
from itzraven.core.graph_memory import GraphMemory, EntityType, get_graph_memory


def test_visualizer_initialization():
    graph = get_graph_memory(namespace="test_viz")
    viz = AttackGraphVisualizer(graph=graph)
    assert viz is not None
    graph.clear()


def test_generate_html():
    graph = get_graph_memory(namespace="test_viz2")
    graph.add_entity(EntityType.DOMAIN, "example.com")
    graph.add_entity(EntityType.IP_ADDRESS, "93.184.216.34")
    viz = AttackGraphVisualizer(graph=graph)
    html = viz.generate_html()
    assert "<html" in html
    assert "d3.v7" in html
    assert "example.com" in html
    graph.clear()


def test_generate_html_with_output(tmp_path):
    graph = get_graph_memory(namespace="test_viz3")
    graph.add_entity(EntityType.PORT, "443/tcp", properties={"port": 443})
    viz = AttackGraphVisualizer(graph=graph)
    out_path = str(tmp_path / "test_graph.html")
    html = viz.generate_html(output_path=out_path)
    assert tmp_path.joinpath("test_graph.html").exists()
    graph.clear()

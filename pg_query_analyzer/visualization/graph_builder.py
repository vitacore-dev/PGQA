"""Build graph data structures for plan visualization."""

from collections import defaultdict


def create_graph_data_from_plan(plan_tree):
    """Create visual graph data from the internal plan-tree structure."""
    if not plan_tree:
        return {"nodes": [], "edges": []}

    graph_data = {
        "nodes": [],
        "edges": [],
        "incoming_edges": defaultdict(int),
    }

    def add_nodes_recursive(node, pos_y=0, level_width=1, is_main_node=False):
        if not node or "id" not in node:
            return

        node_id = str(id(node))
        if node == plan_tree:
            is_main_node = True

        graph_data["nodes"].append(
            {
                "id": node_id,
                "type": node.get("type", "Unknown"),
                "properties": node.get("properties", {}),
                "cost": node.get("cost", 0),
                "rows": node.get("rows", 0),
                "depth": node.get("depth", 0),
                "pos_y": pos_y,
                "is_main_node": is_main_node,
            }
        )

        children = node.get("children", [])
        for i, child in enumerate(children):
            child_id = str(id(child))
            graph_data["edges"].append(
                {
                    "from": child_id,
                    "to": node_id,
                    "arrows": "to",
                    "width": 2,
                    "smooth": {
                        "enabled": True,
                        "type": "dynamic",
                    },
                }
            )
            graph_data["incoming_edges"][node_id] += 1

            child_pos_y = pos_y - level_width / 2 + (i + 0.5) * (level_width / len(children))
            add_nodes_recursive(child, child_pos_y, level_width / len(children))

    add_nodes_recursive(plan_tree)
    return graph_data

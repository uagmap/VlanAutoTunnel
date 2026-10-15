from __future__ import annotations

import unittest

from vlan_tool.trace_panel import LiveTracePanel, ui_print, live_trace_ui, start_trace_panel


class TracePanelTests(unittest.TestCase):
    def test_render_vlan_and_vertical_tree(self) -> None:
        panel = LiveTracePanel()
        panel.set_vlan(140)
        panel.add_hop("c9500.core.example.net", "10.30.1.4", role="L3")
        panel.add_hop("mes2324b.site12a_id1004", "10.20.14.56")
        panel.add_hop("mes2324b.Riverside98-26", "10.20.14.101", role="destination")

        text = "\n".join(panel._render_lines())
        self.assertIn("VLAN: 140", text)
        self.assertIn("[L3] c9500.core.example.net (10.30.1.4)", text)
        self.assertIn("[dest] mes2324b.Riverside98-26 (10.20.14.101)", text)
        self.assertIn("↓", text)

    def test_duplicate_host_not_added_twice(self) -> None:
        panel = LiveTracePanel()
        panel.add_hop("sw", "10.20.1.1", role="L3")
        panel.add_hop("sw", "10.20.1.1")
        self.assertEqual(len(panel.hops), 1)

    def test_emit_records_lines_without_live(self) -> None:
        panel = LiveTracePanel()
        panel.emit("hello debug")
        self.assertEqual(list(panel._lines), ["hello debug"])

    def test_ui_print_uses_active_panel(self) -> None:
        with live_trace_ui() as panel:
            # Non-TTY CI: Live may be disabled; emit path still records.
            ui_print("from ui_print")
            self.assertIs(start_trace_panel(), panel)
            self.assertIn("from ui_print", list(panel._lines))


if __name__ == "__main__":
    unittest.main()

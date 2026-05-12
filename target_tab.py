from urllib.parse import urlparse
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from typing import Dict
from constants import *

class TargetTab:

    def create_target_tab(self):
        """Create target tab"""
        target_widget = QWidget()
        layout = QVBoxLayout(target_widget)

        # Site map tree
        site_map_group = QGroupBox("Site Map")
        site_map_layout = QVBoxLayout()

        self.site_map_tree = QTreeWidget()
        self.site_map_tree.setHeaderLabels(["Target", "Requests", "Issues"])
        site_map_layout.addWidget(self.site_map_tree)

        site_map_group.setLayout(site_map_layout)
        layout.addWidget(site_map_group)

        self.tab_widget.addTab(target_widget, "Target")

    def update_site_map(self):
        """Update the site map tree"""
        self.site_map_tree.clear()

        # Group by host
        hosts: Dict[str, Dict[str, int]] = {}

        for finding in self.findings:
            host = finding.get("host", "unknown")

            if host not in hosts:
                hosts[host] = {"requests": 0, "issues": 0}

            hosts[host]["requests"] += 1
            if finding.get("params"):
                hosts[host]["issues"] += 1

        # Add to tree
        for host, data in sorted(hosts.items()):
            item = QTreeWidgetItem([host, str(data["requests"]), str(data["issues"])])

            if data["issues"] > 0:
                item.setForeground(2, QColor(COLOR_HIGH))

            self.site_map_tree.addTopLevelItem(item)

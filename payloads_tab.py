import os
import sys
import traceback
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

from constants import *
try:
    from payloads import get_all_payloads
except ImportError:
    print("❌ Error: payloads.py not found!")
    print("Please ensure payloads.py is in the same directory as hunt_gui.py")
    sys.exit(1)
    
class PayloadsTab:
    def create_payloads_tab(self):
        """Create comprehensive payloads tab for pentesting"""
        payloads_widget = QWidget()
        payloads_layout = QVBoxLayout(payloads_widget)
        payloads_layout.setContentsMargins(8, 8, 8, 8)
        payloads_layout.setSpacing(8)

        # ========================================================================
        # HEADER
        # ========================================================================

        header_container = QWidget()
        header_container.setMaximumHeight(50)
        header_layout = QHBoxLayout(header_container)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(8)

        header = QLabel("💣 ATTACK PAYLOADS & TECHNIQUES")
        header.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT_BRIGHT};
                font-size: {FONT_SIZE_NORMAL};
                font-weight: 700;
                padding: 8px 16px;
                background: linear-gradient(135deg, {COLOR_ELEVATED_BG} 0%, {COLOR_CARD_BG} 100%);
                border-radius: 6px;
                border-left: 3px solid {COLOR_CRITICAL};
            }}
        """
        )
        header_layout.addWidget(header)

        # Search box
        self.payload_search = QLineEdit()
        self.payload_search.setPlaceholderText("🔍 Search payloads...")
        self.payload_search.setMaximumWidth(300)
        self.payload_search.textChanged.connect(self.filter_payloads)
        self.payload_search.setStyleSheet(
            f"""
            QLineEdit {{
                padding: 6px 12px;
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
            }}
            QLineEdit:focus {{
                border-color: {COLOR_ACCENT};
            }}
        """
        )
        header_layout.addWidget(self.payload_search)

        header_layout.addStretch()
        payloads_layout.addWidget(header_container)

        # ========================================================================
        # MAIN SPLITTER - Categories | Payload Display
        # ========================================================================

        main_splitter = QSplitter(Qt.Horizontal)
        main_splitter.setHandleWidth(4)
        main_splitter.setStyleSheet(
            f"""
            QSplitter::handle:horizontal {{
                background-color: {COLOR_BORDER};
            }}
            QSplitter::handle:horizontal:hover {{
                background-color: {COLOR_ACCENT};
            }}
        """
        )

        # ========================================================================
        # LEFT PANEL: Categories Tree
        # ========================================================================

        categories_panel = QWidget()
        categories_panel.setMaximumWidth(350)
        categories_panel.setMinimumWidth(250)
        categories_layout = QVBoxLayout(categories_panel)
        categories_layout.setContentsMargins(0, 0, 0, 0)
        categories_layout.setSpacing(4)

        cat_header = QLabel("📚 PAYLOAD CATEGORIES")
        cat_header.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT_BRIGHT};
                font-weight: 700;
                font-size: {FONT_SIZE_NORMAL};
                padding: 8px;
                background-color: {COLOR_ELEVATED_BG};
                border-radius: 4px;
            }}
        """
        )
        categories_layout.addWidget(cat_header)

        # Categories tree
        self.payloads_tree = QTreeWidget()
        self.payloads_tree.setHeaderHidden(True)
        self.payloads_tree.setStyleSheet(
            f"""
            QTreeWidget {{
                background-color: {COLOR_DARK_BG};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                outline: none;
                padding: 4px;
            }}
            QTreeWidget::item {{
                padding: 8px;
                color: {COLOR_TEXT};
                border-radius: 3px;
            }}
            QTreeWidget::item:selected {{
                background-color: {COLOR_ACCENT};
                color: white;
            }}
            QTreeWidget::item:hover {{
                background-color: {COLOR_HOVER};
            }}
            QTreeWidget::branch {{
                background: transparent;
            }}
        """
        )

        # Populate categories
        self.populate_payload_categories()

        self.payloads_tree.itemClicked.connect(self.load_payload_content)
        categories_layout.addWidget(self.payloads_tree)

        main_splitter.addWidget(categories_panel)

        # ========================================================================
        # RIGHT PANEL: Payload Display
        # ========================================================================

        display_panel = QWidget()
        display_layout = QVBoxLayout(display_panel)
        display_layout.setContentsMargins(0, 0, 0, 0)
        display_layout.setSpacing(8)

        # Toolbar
        toolbar = QWidget()
        toolbar.setStyleSheet(
            f"""
            QWidget {{
                background-color: {COLOR_ELEVATED_BG};
                border-radius: 4px;
                padding: 4px;
            }}
        """
        )
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(8, 4, 8, 4)

        self.payload_title = QLabel("👈 Select a payload category")
        self.payload_title.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT_BRIGHT};
                font-size: {FONT_SIZE_LARGE};
                font-weight: 700;
                padding: 4px;
            }}
        """
        )
        toolbar_layout.addWidget(self.payload_title)

        toolbar_layout.addStretch()

        # Copy button
        copy_btn = QPushButton("📋 Copy All")
        copy_btn.setToolTip("Copy all payloads to clipboard")
        copy_btn.clicked.connect(self.copy_payload_content)
        copy_btn.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {COLOR_ACCENT};
                color: white;
                padding: 6px 16px;
                border-radius: 4px;
                font-weight: 600;
                border: none;
            }}
            QPushButton:hover {{
                background-color: {COLOR_ACCENT_SECONDARY};
            }}
        """
        )
        toolbar_layout.addWidget(copy_btn)

        # Save button
        save_btn = QPushButton("💾 Save")
        save_btn.setToolTip("Save payloads to file")
        save_btn.clicked.connect(self.save_payload_content)
        save_btn.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {COLOR_LOW};
                color: white;
                padding: 6px 16px;
                border-radius: 4px;
                font-weight: 600;
                border: none;
            }}
            QPushButton:hover {{
                background-color: {COLOR_SUCCESS};
            }}
        """
        )
        toolbar_layout.addWidget(save_btn)

        display_layout.addWidget(toolbar)

        # Payload content display
        self.payload_display = QTextEdit()
        self.payload_display.setReadOnly(True)
        self.payload_display.setPlaceholderText(
            "Select a payload from the categories on the left..."
        )
        self.payload_display.setStyleSheet(
            f"""
            QTextEdit {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 16px;
                font-family: {FONT_FAMILY_MONO};
                font-size: {FONT_SIZE_SMALL};
                line-height: 1.6;
            }}
            QTextEdit:focus {{
                border-color: {COLOR_ACCENT};
            }}
        """
        )
        display_layout.addWidget(self.payload_display)

        main_splitter.addWidget(display_panel)

        # Set splitter sizes
        main_splitter.setSizes([300, 900])

        payloads_layout.addWidget(main_splitter)

        # Add tab
        self.tab_widget.addTab(payloads_widget, "💣 Payloads")

    def populate_payload_categories(self):
        """Populate the payload categories tree from payloads.py"""

        # Get all payloads from the library
        all_payloads = get_all_payloads()

        # Iterate through categories and create tree structure
        for category_name, payloads_dict in all_payloads.items():
            # Create category item
            category_item = QTreeWidgetItem([category_name])
            category_item.setData(0, Qt.UserRole, None)  # No handler for category

            # Style category items
            font = category_item.font(0)
            font.setBold(True)
            font.setPointSize(10)
            category_item.setFont(0, font)

            # Add payload items under category
            for payload_name, payload_func in payloads_dict.items():
                child_item = QTreeWidgetItem([f"  • {payload_name}"])
                child_item.setData(
                    0, Qt.UserRole, payload_func
                )  # Store handler function
                category_item.addChild(child_item)

            # Add category to tree
            self.payloads_tree.addTopLevelItem(category_item)

        # Expand all categories by default
        self.payloads_tree.expandAll()

    def load_payload_content(self, item, column):
        """Load payload content when item is clicked"""
        handler = item.data(0, Qt.UserRole)

        if handler:
            # Get the payload name
            name = item.text(0).strip().replace("• ", "")
            self.payload_title.setText(f"📌 {name}")

            # Show loading message
            self.payload_display.setPlainText("⏳ Generating payloads...")
            QApplication.processEvents()  # Force UI update

            try:
                # Call handler and get result
                result = handler()

                # Display in payload tab
                if result:
                    self.payload_display.setPlainText(result)
                    self.status_label.setText("✅ Payloads loaded")
                    QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))

            except Exception as e:
                error_msg = f"❌ Error generating payload:\n\n{str(e)}"
                self.payload_display.setPlainText(error_msg)
                import traceback

                traceback.print_exc()

    def filter_payloads(self, search_text):
        """Filter payloads based on search"""
        search_text = search_text.lower()

        if not search_text:
            # Show all items
            iterator = QTreeWidgetItemIterator(self.payloads_tree)
            while iterator.value():
                iterator.value().setHidden(False)
                iterator += 1
            return

        # Hide all items first
        iterator = QTreeWidgetItemIterator(self.payloads_tree)
        while iterator.value():
            iterator.value().setHidden(True)
            iterator += 1

        # Show matching items and their parents
        iterator = QTreeWidgetItemIterator(self.payloads_tree)
        while iterator.value():
            item = iterator.value()

            if item.childCount() == 0:  # Leaf node (actual payload)
                item_text = item.text(0).lower()
                if search_text in item_text:
                    # Show this item
                    item.setHidden(False)

                    # Show parent category
                    parent = item.parent()
                    if parent:
                        parent.setHidden(False)
                        parent.setExpanded(True)

            iterator += 1

    def copy_payload_content(self):
        """Copy payload content to clipboard"""
        content = self.payload_display.toPlainText()
        if content and content != "⏳ Generating payloads...":
            clipboard = QApplication.clipboard()
            clipboard.setText(content)
            self.status_label.setText("📋 Payloads copied to clipboard!")
            QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))
        else:
            self.status_label.setText("⚠️ No payload content to copy")
            QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))

    def save_payload_content(self):
        """Save payload content to file"""
        content = self.payload_display.toPlainText()
        if content and content != "⏳ Generating payloads...":
            filename, _ = QFileDialog.getSaveFileName(
                self,
                "Save Payloads",
                "",
                "Text Files (*.txt);;Markdown (*.md);;All Files (*)",
            )
            if filename:
                try:
                    with open(filename, "w", encoding="utf-8") as f:
                        f.write(content)
                    self.status_label.setText(f"💾 Saved to {filename}")
                    QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Failed to save: {e}")
        else:
            self.status_label.setText("⚠️ No payload content to save")
            QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspection Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

APPLET_ID = 'linspectacles-kernel-modules'
APPLET_NAME = 'Kernel Modules'
APPLET_VERSION = '1.0.7'
APPLET_AUTHOR = "brunonlinespace"
APPLET_EDITOR = "brunonlinespace"

import subprocess
from pathlib import Path
from PyQt6.QtCore import QSettings, Qt, QUrl
from PyQt6.QtGui import QBrush, QColor, QKeySequence, QPixmap, QShortcut, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QTabWidget,
    QTextEdit, QVBoxLayout, QWidget,
)
from ._support import BaseInspectorTab, export_records_dialog, metadata_font_qss


_TAINT_BIT_MEANINGS = {
    0: ("P", "proprietary module was loaded"),
    1: ("F", "a module was force loaded"),
    2: ("S", "kernel is running on an out-of-specification system"),
    3: ("R", "a module was force unloaded"),
    4: ("M", "processor reported a Machine Check Exception"),
    5: ("B", "bad page or unexpected page flags were reported"),
    6: ("U", "taint was requested by userspace"),
    7: ("D", "kernel reported an OOPS or BUG"),
    8: ("A", "an ACPI table was overridden"),
    9: ("W", "kernel issued a warning"),
    10: ("C", "a staging driver was loaded"),
    11: ("I", "kernel applied a platform-firmware workaround"),
    12: ("O", "an externally built (out-of-tree) module was loaded"),
    13: ("E", "an unsigned module was loaded"),
    14: ("L", "a soft lockup occurred"),
    15: ("K", "kernel has been live patched"),
    16: ("X", "distribution-defined auxiliary taint"),
    17: ("T", "kernel was built with the randstruct plugin"),
    18: ("N", "an in-kernel test has been run"),
    19: ("J", "userspace used a mutating fwctl debug operation"),
}
_TAINT_LETTER_MEANINGS = {letter: meaning for _bit, (letter, meaning) in _TAINT_BIT_MEANINGS.items()}


def _read_text_file(path):
    path = Path(path)
    try:
        return "observed", path.read_text(encoding="utf-8", errors="replace").strip()
    except PermissionError:
        return "restricted", ""
    except FileNotFoundError:
        return "unavailable", ""
    except OSError as exc:
        return "error", str(exc)


def _read_module_sysfs_value(module_name, filename):
    return _read_text_file(Path("/sys/module") / module_name / filename)


def _module_holders(module_name):
    path = Path("/sys/module") / module_name / "holders"
    try:
        if not path.is_dir():
            return "unavailable", []
        return "observed", sorted(item.name for item in path.iterdir())
    except PermissionError:
        return "restricted", []
    except OSError as exc:
        return "error", [str(exc)]


def _module_parameters(module_name):
    path = Path("/sys/module") / module_name / "parameters"
    try:
        if not path.is_dir():
            return "unavailable", []
        rows = []
        for item in sorted(path.iterdir(), key=lambda x: x.name.lower()):
            if not item.is_file():
                continue
            state, value = _read_text_file(item)
            if state == "observed":
                value = value if value != "" else "(empty)"
            elif state == "restricted":
                value = "Restricted"
            elif state == "unavailable":
                value = "Unavailable"
            else:
                value = f"Error: {value}"
            rows.append((item.name, value))
        return "observed", rows
    except PermissionError:
        return "restricted", []
    except OSError as exc:
        return "error", [("Error", str(exc))]


def _parse_modinfo(text):
    fields = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields.setdefault(key.strip().lower(), []).append(value.strip())
    return fields


def _decode_global_taint(raw_value):
    try:
        value = int(str(raw_value).strip(), 10)
    except (TypeError, ValueError):
        return []
    decoded = []
    for bit, (letter, meaning) in sorted(_TAINT_BIT_MEANINGS.items()):
        if value & (1 << bit):
            decoded.append((bit, letter, meaning))
    return decoded


def _decode_module_taint(raw_value):
    text = str(raw_value or "").strip()
    if not text:
        return []
    decoded = []
    for letter in text:
        if letter.isspace() or letter in "_G":
            continue
        decoded.append((letter, _TAINT_LETTER_MEANINGS.get(letter, "marker meaning not mapped by this applet")))
    return decoded


def _format_bytes(value):
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return str(value)
    units = ["B", "KiB", "MiB", "GiB"]
    amount = float(number)
    unit = units[0]
    for candidate in units:
        unit = candidate
        if amount < 1024 or candidate == units[-1]:
            break
        amount /= 1024.0
    if unit == "B":
        return f"{number:,} B"
    return f"{amount:.2f} {unit} ({number:,} B)"


class KernelSymbolsDialog(QDialog):
    """Read-only symbol browser for one selected loaded kernel module."""

    MAX_SYMBOLS = 10000

    def __init__(self, module_name, parent=None):
        super().__init__(parent)
        self.module_name = str(module_name)
        self._symbols = []
        self.setWindowTitle(f"Kernel Symbols - {self.module_name}")
        self.resize(920, 620)

        root = QVBoxLayout(self)
        title = QLabel(f"Symbols associated with loaded module: {self.module_name}")
        font = title.font()
        font.setBold(True)
        font.setPointSize(max(font.pointSize(), 11))
        title.setFont(font)
        root.addWidget(title)

        note = QLabel("Read-only lookup from /proc/kallsyms. Symbol addresses may be hidden by the kernel's kptr_restrict policy.")
        note.setWordWrap(True)
        root.addWidget(note)

        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Filter Symbol:"))
        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Filter symbol names within this module...")
        self.search_entry.textChanged.connect(self._filter)
        search_row.addWidget(self.search_entry, 1)
        root.addLayout(search_row)

        self.status_label = QLabel("Reading /proc/kallsyms...")
        root.addWidget(self.status_label)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Address", "Type", "Symbol"] )
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0, 170)
        self.table.setColumnWidth(1, 60)
        root.addWidget(self.table, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        root.addWidget(buttons)

        self._load_symbols()

    def _load_symbols(self):
        path = Path("/proc/kallsyms")
        if not path.is_file():
            self.status_label.setText("/proc/kallsyms is not available on this system.")
            return
        tag = f"[{self.module_name}]"
        symbols = []
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    parts = line.split()
                    if len(parts) < 4 or parts[-1] != tag:
                        continue
                    symbols.append((parts[0], parts[1], parts[2]))
                    if len(symbols) >= self.MAX_SYMBOLS:
                        break
        except PermissionError:
            self.status_label.setText("Permission denied reading /proc/kallsyms.")
            return
        except OSError as exc:
            self.status_label.setText(f"Could not read /proc/kallsyms: {exc}")
            return

        self._symbols = symbols
        restricted = bool(symbols) and all(set(address) <= {"0"} for address, _kind, _name in symbols)
        if not symbols:
            self.status_label.setText(
                "No tagged symbols were found for this module. The kernel may not expose module symbol ownership in this configuration."
            )
        elif restricted:
            self.status_label.setText(
                f"{len(symbols)} symbol(s). Addresses are restricted (likely kernel.kptr_restrict); symbol names remain available."
            )
        elif len(symbols) >= self.MAX_SYMBOLS:
            self.status_label.setText(f"Showing the first {self.MAX_SYMBOLS} symbols for this module.")
        else:
            self.status_label.setText(f"{len(symbols)} symbol(s) associated with this module.")
        self._filter()

    def _filter(self, *_):
        query = self.search_entry.text().strip().lower()
        rows = [row for row in self._symbols if not query or query in row[2].lower()]
        self.table.setRowCount(len(rows))
        for row_index, (address, kind, symbol) in enumerate(rows):
            self.table.setItem(row_index, 0, QTableWidgetItem(address))
            self.table.setItem(row_index, 1, QTableWidgetItem(kind))
            self.table.setItem(row_index, 2, QTableWidgetItem(symbol))



class KernelModulesOptionsDialog(QDialog):
    """Established LinSpectacles Options treatment for Kernel Modules."""

    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.setWindowTitle("Options — Kernel Modules")
        self.resize(980, 720)

        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        # Appearance
        appearance_page = QWidget()
        appearance_layout = QVBoxLayout(appearance_page)
        appearance_layout.setContentsMargins(12, 12, 12, 12)
        appearance_layout.setSpacing(10)

        appearance_heading = QLabel("Metadata display")
        heading_font = appearance_heading.font()
        heading_font.setBold(True)
        appearance_heading.setFont(heading_font)
        appearance_layout.addWidget(appearance_heading)

        appearance_note = QLabel(
            "Choose how the inventory and Metadata Details panes are arranged. "
            "This Kernel Modules setting is remembered."
        )
        appearance_note.setWordWrap(True)
        appearance_layout.addWidget(appearance_note)

        layout_row = QHBoxLayout()
        layout_row.addWidget(QLabel("Record details layout:"))
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Horizontal", "Vertical"])
        self.layout_combo.setCurrentText(
            "Vertical" if owner.details_orientation == "vertical" else "Horizontal"
        )
        self.layout_combo.currentTextChanged.connect(self._layout_changed)
        layout_row.addWidget(self.layout_combo)
        layout_row.addStretch(1)
        appearance_layout.addLayout(layout_row)

        self.show_metadata_panel = QCheckBox("Show Metadata Details panel (F3)")
        self.show_metadata_panel.setChecked(owner.metadata_panel_visible)
        self.show_metadata_panel.toggled.connect(self._metadata_panel_changed)
        appearance_layout.addWidget(self.show_metadata_panel)

        shortcut_note = QLabel(
            "F3 hides/restores Metadata Details. Shift+F5 refreshes the module inventory. "
            "Ctrl+L toggles Horizontal/Vertical layout. Ctrl+/ opens Options. F4 opens Symbols. "
            "Category: Ctrl+1 = Audio / Sound; Ctrl+2 = Network / Wireless; "
            "Ctrl+3 = Graphics / Display; Ctrl+4 = Storage / Filesystems; "
            "Ctrl+5 = USB / Input Devices; Ctrl+6 = CPU / Core / System; "
            "Ctrl+7 = Other / Uncategorized; Ctrl+A = All Categories."
        )
        shortcut_note.setWordWrap(True)
        appearance_layout.addWidget(shortcut_note)

        appearance_layout.addStretch(1)
        tabs.addTab(appearance_page, "Appearance")

        # Sources
        sources_page = QWidget()
        sources_layout = QVBoxLayout(sources_page)
        sources_layout.setContentsMargins(12, 12, 12, 12)
        sources_layout.setSpacing(10)

        sources_heading = QLabel("Data Sources")
        sources_heading_font = sources_heading.font()
        sources_heading_font.setBold(True)
        sources_heading_font.setPointSize(max(sources_heading_font.pointSize(), 11))
        sources_heading.setFont(sources_heading_font)
        sources_layout.addWidget(sources_heading)

        sources_note = QLabel(
            "Linux interfaces used by this read-only kernel-module inspector."
        )
        sources_note.setWordWrap(True)
        sources_layout.addWidget(sources_note)

        sources_text = QTextEdit()
        sources_text.setReadOnly(True)
        sources_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        chosen_font = getattr(owner, "_metadata_font", None)
        if chosen_font is not None:
            sources_text.setFont(chosen_font)
            sources_text.document().setDefaultFont(chosen_font)
            sources_text.setCurrentFont(chosen_font)
            font_rule = metadata_font_qss(chosen_font)
        else:
            font_rule = ""
        sources_text.setStyleSheet(
            "QTextEdit { "
            + font_rule
            + " background-color: #151719; color: #dcdcdc; "
              "border: 1px solid #333333; }"
        )

        source_key_format = QTextCharFormat()
        source_key_format.setForeground(QColor("#9cdcfe"))
        source_key_format.setFontWeight(600)
        source_value_format = QTextCharFormat()
        source_value_format.setForeground(QColor("#dcdcdc"))

        cursor = sources_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        for line in owner.sources_text().splitlines():
            if line and not line[:1].isspace():
                cursor.insertText(line + "\n", source_key_format)
            else:
                cursor.insertText(line + "\n", source_value_format)
        sources_text.setTextCursor(cursor)
        sources_text.moveCursor(QTextCursor.MoveOperation.Start)
        sources_layout.addWidget(sources_text, 1)
        tabs.addTab(sources_page, "Sources")

        # Export
        export_page = QWidget()
        export_layout = QVBoxLayout(export_page)
        export_layout.setContentsMargins(12, 12, 12, 12)
        export_layout.setSpacing(10)

        export_heading = QLabel("Export details")
        export_heading_font = export_heading.font()
        export_heading_font.setBold(True)
        export_heading.setFont(export_heading_font)
        export_layout.addWidget(export_heading)

        export_note = QLabel(
            "Select the Kernel Modules details to include in the export."
        )
        export_note.setWordWrap(True)
        export_layout.addWidget(export_note)

        self.export_name = QCheckBox("Module Name")
        self.export_category = QCheckBox("Category")
        self.export_size = QCheckBox("Size")
        self.export_use_count = QCheckBox("Use Count")
        self.export_used_by = QCheckBox("Holders / Used By")
        self.export_metadata = QCheckBox("Metadata Details")

        for checkbox in (
            self.export_name,
            self.export_category,
            self.export_size,
            self.export_use_count,
            self.export_used_by,
        ):
            checkbox.setChecked(True)
        self.export_metadata.setChecked(False)

        for checkbox in (
            self.export_name,
            self.export_category,
            self.export_size,
            self.export_use_count,
            self.export_used_by,
            self.export_metadata,
        ):
            export_layout.addWidget(checkbox)

        export_layout.addStretch(1)
        export_row = QHBoxLayout()
        export_row.addStretch(1)
        export_button = QPushButton("Export...")
        export_button.clicked.connect(self._export_selected)
        export_row.addWidget(export_button)
        export_layout.addLayout(export_row)
        tabs.addTab(export_page, "Export")

        # About
        about_page = QWidget()
        about_layout = QVBoxLayout(about_page)
        about_layout.setContentsMargins(24, 20, 24, 18)
        about_layout.setSpacing(8)

        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setFixedSize(112, 112)
        icon_path = Path(__file__).resolve().parent / "icon.png"
        if icon_path.is_file():
            pixmap = QPixmap(str(icon_path))
            if not pixmap.isNull():
                icon_label.setPixmap(
                    pixmap.scaled(
                        112,
                        112,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                )
        about_layout.addWidget(icon_label, alignment=Qt.AlignmentFlag.AlignHCenter)

        name = QLabel("<h2 style='margin:0'>Kernel Modules</h2>")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(name)

        version = QLabel(f"Version {APPLET_VERSION}")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(version)

        slogan = QLabel("<b>Expose. Explore. Explain.</b>")
        slogan.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(slogan)

        description = QLabel(
            "A read-only LinSpectacles applet for inspecting loaded kernel modules, "
            "runtime module state, taint context and selected-module symbols."
        )
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(description)

        details = QLabel(
            "<b>Build:</b> Standalone LinSpectacles applet<br>"
            "<b>Organisation ID:</b> "
            "<a href='https://github.com/linspectacles/'>linspectacles</a><br>"
            f"<b>Applet ID:</b> {APPLET_ID}"
        )
        details.setWordWrap(True)
        details.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction
            | Qt.TextInteractionFlag.TextSelectableByMouse
        )
        details.setOpenExternalLinks(True)
        details.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(details)

        copyright_label = QLabel(
            "Copyright © 2026 "
            "<a href='https://github.com/brunonlinespace'>brunonlinespace</a>"
        )
        copyright_label.setOpenExternalLinks(True)
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(copyright_label)

        license_label = QLabel("Licensed under GNU GPLv3 or later.")
        license_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(license_label)

        root_dir = Path(__file__).resolve().parent.parent
        readme_url = QUrl.fromLocalFile(str(root_dir / "README.md")).toString()
        license_url = QUrl.fromLocalFile(str(root_dir / "LICENSE")).toString()
        links = QLabel(
            f"<a href='{readme_url}'>README</a> "
            "&nbsp;·&nbsp; "
            f"<a href='{license_url}'>License</a> "
            "&nbsp;·&nbsp; "
            "<a href='https://github.com/linspectacles/kernel-modules'>Repository</a>"
        )
        links.setOpenExternalLinks(True)
        links.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(links)
        about_layout.addStretch(1)
        tabs.addTab(about_page, "About")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _layout_changed(self, text):
        self.owner.set_details_orientation(str(text).strip().lower(), persist=True)

    def _metadata_panel_changed(self, visible):
        self.owner.set_metadata_panel_visible(bool(visible), persist=True)

    def _export_selected(self):
        selected = []
        if self.export_name.isChecked():
            selected.append(("name", "Module Name", 170, "left"))
        if self.export_category.isChecked():
            selected.append(("category", "Category", 150, "left"))
        if self.export_size.isChecked():
            selected.append(("size", "Size", 95, "right"))
        if self.export_use_count.isChecked():
            selected.append(("use_count", "Use Count", 85, "right"))
        if self.export_used_by.isChecked():
            selected.append(("used_by", "Holders / Used By", 150, "left"))
        if self.export_metadata.isChecked():
            selected.append(("metadata_details", "Metadata Details", 520, "left"))

        if not selected:
            QMessageBox.information(self, "Export", "Select at least one detail to export.")
            return

        records = []
        include_metadata = self.export_metadata.isChecked()
        for record in self.owner.get_export_records():
            exported = dict(record)
            if include_metadata:
                exported["metadata_details"] = self.owner.metadata_details_for_export(record)
            records.append(exported)

        if not records:
            QMessageBox.information(self, "Export", "There is no collected data to export yet.")
            return

        path = export_records_dialog(
            self,
            APPLET_NAME,
            records,
            columns=selected,
        )
        if path is not None:
            self.owner.set_status(f"Exported data to {path}")



class KernelTab(BaseInspectorTab):
    NUMERIC_COLUMNS = {"size", "use_count"}

    def __init__(self, parent=None):
        columns = [
            ("name", "Module Name", 170, "left"),
            ("category", "Category", 150, "left"),
            ("size", "Size", 95, "right"),
            ("use_count", "Use Count", 85, "right"),
            ("used_by", "Holders / Used By", 150, "left"),
        ]
        categories = [
            "All Categories",
            "Audio / Sound",
            "Network / Wireless",
            "Graphics / Display",
            "Storage / Filesystems",
            "USB / Input Devices",
            "CPU / Core / System",
            "Other / Uncategorized",
        ]
        super().__init__("Total Loaded Modules", columns, categories, parent)
        self.export_title = APPLET_NAME
        self._selected_module_name = None

        # Established compact top bar: Symbols... | Refresh List | Options...
        self.symbols_btn = QPushButton("Symbols...")
        self.symbols_btn.setToolTip("Browse /proc/kallsyms symbols associated with the selected loaded module.")
        self.symbols_btn.setEnabled(False)
        self.symbols_btn.clicked.connect(self.show_symbols)
        refresh_index = self.dash_layout.indexOf(self.refresh_btn)
        self.dash_layout.insertWidget(refresh_index, self.symbols_btn)

        self.details_orientation = "horizontal"
        self._load_details_orientation()

        self.metadata_panel_visible = True
        self._load_metadata_panel_visibility()

        self.export_btn.setText("Options...")
        try:
            self.export_btn.clicked.disconnect()
        except TypeError:
            pass
        self.export_btn.clicked.connect(self.show_options)
        self.export_btn.setEnabled(True)

        self._shortcuts = []
        self._install_shortcuts()

        self.load_modules()

    @staticmethod
    def classify_module(name):
        name_lower = name.lower()
        if any(k in name_lower for k in ("snd", "sound", "audio", "codec", "dsp")):
            return "Audio / Sound"
        if any(k in name_lower for k in ("net", "eth", "wifi", "wlan", "wireless", "bluetooth", "bt", "ipv", "nf_")):
            return "Network / Wireless"
        if any(k in name_lower for k in ("drm", "gpu", "amdgpu", "i915", "nouveau", "nvidia", "display", "fb")):
            return "Graphics / Display"
        if any(k in name_lower for k in ("ext4", "btrfs", "xfs", "fat", "vfat", "scsi", "nvme", "ata", "usb-storage")):
            return "Storage / Filesystems"
        if any(k in name_lower for k in ("usb", "hid", "input", "evdev", "keyboard", "mouse")):
            return "USB / Input Devices"
        if any(k in name_lower for k in ("cpu", "intel", "amd", "acpi", "thermal", "power", "sched", "core")):
            return "CPU / Core / System"
        return "Other / Uncategorized"

    def style_table_item(self, item, column_id, record):
        if column_id != "category":
            return

        color_map = {
            "Audio / Sound": "#ce9178",
            "Network / Wireless": "#4ec9b0",
            "Graphics / Display": "#dcdcaa",
            "Storage / Filesystems": "#c586c0",
            "USB / Input Devices": "#9cdcfe",
            "CPU / Core / System": "#b5cea8",
            "Other / Uncategorized": "#9a9a9a",
        }

        color = color_map.get(record.get("category"))
        if color:
            item.setForeground(QBrush(QColor(color)))

    def load_modules(self):
        self.modules_data.clear()
        self._selected_module_name = None
        if hasattr(self, "symbols_btn"):
            self.symbols_btn.setEnabled(False)
        try:
            with open("/proc/modules", "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    try:
                        size = int(parts[1])
                    except ValueError:
                        size = 0
                    try:
                        use_count = int(parts[2]) if len(parts) > 2 else 0
                    except ValueError:
                        use_count = 0
                    self.modules_data.append({
                        "name": parts[0],
                        "size": size,
                        "use_count": use_count,
                        "used_by": parts[3] if len(parts) > 3 else "-",
                        "proc_state": parts[4] if len(parts) > 4 else "",
                        "proc_address": parts[5] if len(parts) > 5 else "",
                        "category": self.classify_module(parts[0]),
                    })

            self.modules_data.sort(key=lambda record: record.get("name", "").lower())

            self.stats_label.setText(
                f"{self.total_label_text}: {len(self.modules_data)}"
            )
            self.clear_info()
            self.filter_modules()
            self.set_status("Successfully refreshed kernel modules.")
        except FileNotFoundError:
            self.set_status("Warning: /proc/modules not found (Linux required).")
        except Exception as exc:
            self.set_status(f"Error reading kernel modules: {exc}")

    def on_module_select(self):
        record = self.current_record()
        if not record:
            return

        mod_name = record["name"]
        self._selected_module_name = mod_name
        self.symbols_btn.setEnabled(True)

        modinfo_state = self._render_record_details(record)

        if modinfo_state == "observed":
            self.set_status(f"Inspecting reported and runtime metadata for [{mod_name}].")
        elif modinfo_state == "unavailable":
            self.set_status(f"Runtime data shown for [{mod_name}]; modinfo is unavailable.")
        else:
            self.set_status(f"Runtime data shown for [{mod_name}]; modinfo did not complete normally.")

    def _render_record_details(self, record):
        self.clear_info()
        mod_name = record["name"]

        self.append_info("--- Reported Module Metadata (modinfo) ---\n")
        modinfo_fields = {}
        modinfo_state = "observed"
        try:
            result = subprocess.run(
                ["modinfo", "--", mod_name],
                capture_output=True,
                text=True,
                check=False,
                timeout=8,
            )
        except FileNotFoundError:
            modinfo_state = "unavailable"
            self.append_info("modinfo command is not installed or not available in PATH.\n")
        except subprocess.TimeoutExpired:
            modinfo_state = "error"
            self.append_info("modinfo timed out while reading module metadata.\n")
        except Exception as exc:
            modinfo_state = "error"
            self.append_info(f"modinfo failed: {exc}\n")
        else:
            output = result.stdout or result.stderr
            modinfo_fields = _parse_modinfo(result.stdout)
            if not output:
                self.append_info("No module metadata was returned.\n")
            else:
                for line in output.splitlines():
                    if ":" in line:
                        key, value = line.split(":", 1)
                        self.append_key_value(key.strip(), value.strip())
                    else:
                        self.append_info(line + "\n", "value")
            if result.returncode != 0:
                modinfo_state = "error"

        self._append_runtime_details(mod_name, record, modinfo_fields)
        self.info_text.moveCursor(QTextCursor.MoveOperation.Start)
        self.info_text.verticalScrollBar().setValue(0)
        return modinfo_state

    def _append_runtime_details(self, mod_name, record, modinfo_fields):
        module_root = Path("/sys/module") / mod_name
        self.append_info("\n--- Runtime State ---\n")
        self.append_key_value("Inventory Source", "/proc/modules")
        self.append_key_value("Listed in /proc/modules", "Yes")
        self.append_key_value("Reported State", record.get("proc_state") or "Not reported")
        self.append_key_value("Use Count", record.get("use_count", "Not reported"))
        self.append_key_value("Reported Size", _format_bytes(record.get("size", 0)))
        self.append_key_value("Runtime sysfs Path", str(module_root) if module_root.exists() else "Not exposed")

        for filename, label, formatter in (
            ("refcnt", "Runtime Refcount", None),
            ("initstate", "Init State", None),
            ("coresize", "Core Size", _format_bytes),
            ("initsize", "Init Size", _format_bytes),
            ("version", "Runtime Version", None),
            ("srcversion", "Source Version", None),
        ):
            state, value = _read_module_sysfs_value(mod_name, filename)
            if state == "observed":
                shown = formatter(value) if formatter else (value or "(empty)")
                self.append_key_value(label, shown)
            elif state == "restricted":
                self.append_key_value(label, "Restricted")

        filenames = modinfo_fields.get("filename", [])
        if filenames:
            filename = filenames[0]
            self.append_key_value("Module File (modinfo)", filename)
            if filename == "(builtin)":
                self.append_key_value("Load Form", "Reported by modinfo as built into the kernel")
            elif filename:
                self.append_key_value("Load Form", "modinfo reports an external module file")
        else:
            self.append_key_value("Load Form", "Not determined")

        self.append_info("\n--- Runtime Parameters ---\n")
        parameter_state, parameters = _module_parameters(mod_name)
        if parameter_state == "observed" and parameters:
            for name, value in parameters:
                # Indent continuation lines while retaining the exact text that was readable.
                text = str(value).replace("\n", "\n    ")
                self.append_key_value(name, text)
        elif parameter_state == "observed":
            self.append_info("No runtime parameter files are exposed for this module.\n")
        elif parameter_state == "restricted":
            self.append_info("Runtime parameter directory access is restricted.\n")
        elif parameter_state == "unavailable":
            self.append_info("No runtime parameter directory is exposed for this module.\n")
        else:
            self.append_info("Runtime parameter inspection returned an error.\n")

        self.append_info("\n--- Relationships ---\n")
        declared = []
        for value in modinfo_fields.get("depends", []):
            declared.extend(item.strip() for item in value.split(",") if item.strip())
        self.append_key_value(
            "Declared Dependencies (modinfo)",
            ", ".join(dict.fromkeys(declared)) if declared else "None reported",
        )

        holder_state, holders = _module_holders(mod_name)
        if holder_state == "observed":
            self.append_key_value("Current Holders (/sys/module/.../holders)", ", ".join(holders) if holders else "None reported")
        elif holder_state == "restricted":
            self.append_key_value("Current Holders (/sys/module/.../holders)", "Restricted")
        elif holder_state == "unavailable":
            self.append_key_value("Current Holders (/sys/module/.../holders)", "Not exposed")
        else:
            self.append_key_value("Current Holders (/sys/module/.../holders)", f"Error: {'; '.join(holders)}")
        self.append_key_value("Used By (/proc/modules)", record.get("used_by") or "None reported")
        self.append_info(
            "Relationship note: declared dependencies come from module metadata; holders/Used By report current reverse relationships.\n"
        )

        self.append_info("\n--- Taint Information ---\n")
        state, module_taint = _read_module_sysfs_value(mod_name, "taint")
        if state == "observed":
            raw = module_taint or "(none reported)"
            self.append_key_value("Module Taint Markers", raw)
            decoded = _decode_module_taint(module_taint)
            if decoded:
                for letter, meaning in decoded:
                    self.append_key_value(f"Marker {letter}", meaning)
        elif state == "restricted":
            self.append_key_value("Module Taint Markers", "Restricted")
        else:
            self.append_key_value("Module Taint Markers", "Not exposed")

        kernel_state, kernel_taint = _read_text_file("/proc/sys/kernel/tainted")
        if kernel_state == "observed":
            self.append_key_value("Kernel Taint Value (global)", kernel_taint or "0")
            decoded = _decode_global_taint(kernel_taint)
            if decoded:
                self.append_key_value("Kernel Taint Flags (global)", " ".join(letter for _bit, letter, _meaning in decoded))
            else:
                self.append_key_value("Kernel Taint Flags (global)", "None reported")
            self.append_info(
                "Global taint note: /proc/sys/kernel/tainted describes the running kernel as a whole; "
                "LinSpectacles does not attribute global taint flags to this selected module unless the module's own sysfs taint field reports them.\n"
            )

    @staticmethod
    def sources_text():
        return (
            "Kernel Modules is read-only. Its displayed facts come from these interfaces.\n\n"
            "Module inventory, reported size, use count, state and Used By\n"
            "  /proc/modules\n\n"
            "Static module metadata, module file, aliases and declared dependencies\n"
            "  modinfo\n\n"
            "Runtime state, refcount, parameters, holders and module taint markers\n"
            "  /sys/module/<module>/...\n\n"
            "Selected-module exported symbols\n"
            "  /proc/kallsyms\n\n"
            "Global kernel taint value\n"
            "  /proc/sys/kernel/tainted\n\n"
            "Important distinctions\n"
            "  /proc/modules lists modules loaded at runtime; it is not an inventory of every component built into the kernel.\n"
            "  modinfo dependencies are declared metadata, while sysfs holders report current reverse relationships.\n"
            "  The global kernel taint value describes the running kernel as a whole and is not automatically attributable to the selected module.\n"
            "  Runtime parameter files are read only by this applet; Kernel Modules never writes parameter files or changes module state."
        )

    def show_options(self):
        dialog = KernelModulesOptionsDialog(self)
        dialog.exec()

    def _add_shortcut(self, sequence, callback):
        shortcut = QShortcut(QKeySequence(sequence), self)
        shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        shortcut.activated.connect(callback)
        self._shortcuts.append(shortcut)
        return shortcut

    def _install_shortcuts(self):
        self._add_shortcut("F3", self.toggle_metadata_panel)
        self._add_shortcut("Ctrl+L", self.toggle_details_orientation)
        self._add_shortcut("Ctrl+/", self.show_options)
        self._add_shortcut("F4", self.show_symbols)
        self._add_shortcut("Shift+F5", self.load_modules)
        self._add_shortcut("Ctrl+A", lambda: self._select_category(0))
        for index in range(1, 8):
            self._add_shortcut(f"Ctrl+{index}", lambda i=index: self._select_category(i))

    def _select_category(self, index):
        if 0 <= index < self.category_dropdown.count():
            self.category_dropdown.setCurrentIndex(index)

    def toggle_details_orientation(self):
        target = "vertical" if self.details_orientation == "horizontal" else "horizontal"
        self.set_details_orientation(target, persist=True)

    def _load_metadata_panel_visibility(self):
        settings = QSettings("brunonlinespace", "Kernel Modules")
        value = settings.value("metadata_panel_visible", True)
        if isinstance(value, str):
            visible = value.strip().lower() not in {"0", "false", "no", "off"}
        else:
            visible = bool(value)
        self.set_metadata_panel_visible(visible, persist=False)

    def set_metadata_panel_visible(self, visible, *, persist=True):
        self.metadata_panel_visible = bool(visible)
        details_panel = self.splitter.widget(1)
        if details_panel is not None:
            details_panel.setVisible(self.metadata_panel_visible)
        if self.metadata_panel_visible:
            self.set_details_orientation(self.details_orientation, persist=False)
        if persist:
            settings = QSettings("brunonlinespace", "Kernel Modules")
            settings.setValue("metadata_panel_visible", self.metadata_panel_visible)
            settings.sync()

    def toggle_metadata_panel(self):
        self.set_metadata_panel_visible(not self.metadata_panel_visible, persist=True)

    def filter_modules(self, *_):
        super().filter_modules()
        if self.current_record() is None:
            self._selected_module_name = None
            if hasattr(self, "symbols_btn"):
                self.symbols_btn.setEnabled(False)

    def _load_details_orientation(self):
        settings = QSettings("brunonlinespace", "Kernel Modules")
        orientation = str(
            settings.value("details_orientation", "horizontal") or "horizontal"
        ).lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.set_details_orientation(orientation, persist=False)

    def set_details_orientation(self, orientation, *, persist=True):
        orientation = str(orientation or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.details_orientation = orientation

        details_panel = self.splitter.widget(1)
        details_layout = details_panel.layout() if details_panel is not None else None
        if orientation == "vertical":
            self.splitter.setOrientation(Qt.Orientation.Vertical)
            if details_layout is not None:
                details_layout.setContentsMargins(0, 8, 0, 0)
            self.splitter.setSizes([430, 330])
        else:
            self.splitter.setOrientation(Qt.Orientation.Horizontal)
            if details_layout is not None:
                details_layout.setContentsMargins(8, 0, 0, 0)
            self.splitter.setSizes([480, 700])

        if persist:
            settings = QSettings("brunonlinespace", "Kernel Modules")
            settings.setValue("details_orientation", orientation)
            settings.sync()

    def metadata_details_for_export(self, record):
        """Render the same metadata text for one record without changing the visible pane."""
        original_info = self.info_text
        temp = QTextEdit()
        self.info_text = temp
        try:
            self._render_record_details(record)
            return temp.toPlainText()
        finally:
            self.info_text = original_info

    def show_symbols(self):
        if not self._selected_module_name:
            return
        dialog = KernelSymbolsDialog(self._selected_module_name, self)
        dialog.exec()

def create_applet(parent=None):
    return KernelTab(parent=parent)

def run_standalone():
    import sys
    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication, QMainWindow
    from ._support import STANDALONE_STYLESHEET
    app = QApplication(sys.argv)
    app.setApplicationName(APPLET_NAME)
    app.setOrganizationName(APPLET_AUTHOR)
    icon_path = Path(__file__).resolve().parent / "icon.png"
    if icon_path.is_file():
        app.setWindowIcon(QIcon(str(icon_path)))
    app.setStyleSheet(STANDALONE_STYLESHEET)
    window = QMainWindow()
    if icon_path.is_file():
        window.setWindowIcon(QIcon(str(icon_path)))
    window.setWindowTitle(f"{APPLET_NAME} {APPLET_VERSION} — LinSpectacles Applet")
    window.resize(1200, 780)
    window.setCentralWidget(create_applet())
    window.show()
    return app.exec()

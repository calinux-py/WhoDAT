import base64
import re
import socket
import os
import time
import json
import requests
import urllib.parse
from datetime import datetime
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QPixmap, QIcon
from PyQt5.QtWidgets import (
    QMainWindow, QApplication, QTabWidget, QWidget, QVBoxLayout,
    QFormLayout, QLabel, QLineEdit, QPushButton, QTextEdit,
    QHBoxLayout, QMessageBox, QFileDialog
)
from config import (
    get_virustotal_api_key,
    get_safe_browsing_api_key,
    get_urlscan_api_key,
    get_openai_api_key,
    get_hybrid_analysis_api_key
)
from utils import (
    defang_url, defang_email, defang_domain,
    format_field
)
from analysis import (
    AnalyzerThread, HeaderAnalyzerThread, SentimentAnalyzerThread,
    AttachmentAnalyzerThread
)

class MainWindow(QMainWindow):
    icon_base64 = "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"

    def __init__(self):
        super().__init__()

        pixmap = QPixmap()
        if self.icon_base64:
            pixmap.loadFromData(base64.b64decode(self.icon_base64))
        self.setWindowIcon(QIcon(pixmap))

        self.setWindowTitle("WhoDAT - InfoSec Analyzer for Nerds")
        self.resize(1000, 600)
        self.initUI()

    def initUI(self):
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.West)
        self.tabs.setMovable(True)

        self.domain_tab = QWidget()
        self.header_tab = QWidget()
        self.sentiment_tab = QWidget()
        self.attachment_tab = QWidget()

        self.tabs.addTab(self.domain_tab, "Domain Analyzer")
        self.tabs.addTab(self.header_tab, "Header Analyzer")
        self.tabs.addTab(self.sentiment_tab, "Sentiment Analyzer")
        self.tabs.addTab(self.attachment_tab, "Attachment Analyzer")

        self.create_domain_tab()
        self.create_header_tab()
        self.create_sentiment_tab()
        self.create_attachment_tab()

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabs)
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        self.apply_dark_theme()

    def create_domain_tab(self):
        self.email_label = QLabel("Email Address:")
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter email address...")
        font = QFont()
        font.setItalic(True)
        self.email_input.setFont(font)
        self.email_input.setStyleSheet("color: grey;")

        self.link_label = QLabel("URL:")
        self.link_input = QLineEdit()
        self.link_input.setPlaceholderText("Enter URL or link...")
        self.link_input.setFont(font)
        self.link_input.setStyleSheet("color: grey;")

        self.email_input.returnPressed.connect(self.analyze)
        self.link_input.returnPressed.connect(self.analyze)

        self.analyze_button = QPushButton("Analyze")
        self.analyze_button.clicked.connect(self.analyze)

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Segoe UI", 11))

        form_layout = QFormLayout()
        form_layout.addRow(self.email_label, self.email_input)
        form_layout.addRow(self.link_label, self.link_input)

        input_button_layout = QHBoxLayout()
        input_button_layout.addLayout(form_layout)
        input_button_layout.addWidget(self.analyze_button, alignment=Qt.AlignRight)

        layout = QVBoxLayout()
        layout.addLayout(input_button_layout)
        layout.addWidget(self.output_text)

        self.domain_tab.setLayout(layout)

    def create_header_tab(self):
        self.header_label = QLabel("Email Headers:")
        self.header_input = QTextEdit()
        self.header_input.setFixedHeight(150)
        self.header_input.setPlaceholderText("Paste email headers here...")
        font = QFont()
        font.setItalic(True)
        self.header_input.setFont(font)
        self.header_input.setStyleSheet("color: grey;")

        self.header_output_text = QTextEdit()
        self.header_output_text.setReadOnly(True)
        self.header_output_text.setFont(QFont("Segoe UI", 11))

        layout = QVBoxLayout()
        layout.addWidget(self.header_label)
        layout.addWidget(self.header_input)
        layout.addWidget(self.header_output_text)
        self.header_tab.setLayout(layout)

        self.header_input.textChanged.connect(self.analyze_headers)

    def create_sentiment_tab(self):
        self.sentiment_label = QLabel("Email Content:")
        self.sentiment_input = QTextEdit()
        self.sentiment_input.setFixedHeight(150)
        self.sentiment_input.setPlaceholderText("Paste suspicious content here...")
        font = QFont()
        font.setItalic(True)
        self.sentiment_input.setFont(font)
        self.sentiment_input.setStyleSheet("color: grey;")

        self.sentiment_output_text = QTextEdit()
        self.sentiment_output_text.setReadOnly(True)
        self.sentiment_output_text.setFont(QFont("Segoe UI", 11))

        layout = QVBoxLayout()
        layout.addWidget(self.sentiment_label)
        layout.addWidget(self.sentiment_input)
        layout.addWidget(self.sentiment_output_text)
        self.sentiment_tab.setLayout(layout)

        self.sentiment_input.textChanged.connect(self.analyze_sentiment)

    def create_attachment_tab(self):
        self.attachment_label = QLabel("File Attachment:")
        self.attachment_path_input = QLineEdit()
        self.attachment_path_input.setPlaceholderText("Paste file path here...")
        font = QFont()
        font.setItalic(True)
        self.attachment_path_input.setFont(font)
        self.attachment_path_input.setStyleSheet("color: grey;")
        self.attachment_path_input.returnPressed.connect(self.search_file)

        self.browse_button = QPushButton("Browse")
        self.browse_button.setFixedHeight(30)
        self.browse_button.clicked.connect(self.browse_file)

        self.search_button = QPushButton("Search")
        self.search_button.setFixedHeight(30)
        self.search_button.clicked.connect(self.search_file)

        self.attachment_output_text = QTextEdit()
        self.attachment_output_text.setReadOnly(True)
        self.attachment_output_text.setFont(QFont("Segoe UI", 11))

        file_input_layout = QHBoxLayout()
        file_input_layout.addWidget(self.attachment_label)
        file_input_layout.addWidget(self.attachment_path_input)
        file_input_layout.addWidget(self.browse_button)
        file_input_layout.addWidget(self.search_button)

        layout = QVBoxLayout()
        layout.addLayout(file_input_layout)
        layout.addWidget(self.attachment_output_text)

        self.attachment_tab.setLayout(layout)

    def apply_dark_theme(self):
        modern_stylesheet = """
        QWidget {
            background-color: #2b2b2b;
            color: #e0e0e0;
            font-family: 'Segoe UI', sans-serif;
        }
        QLineEdit, QTextEdit {
            background-color: #3c3f41;
            color: #ffffff;
            border: 1px solid #555;
            padding: 5px;
            border-radius: 4px;
        }
        QPushButton {
            background-color: #4a90e2;
            color: #ffffff;
            border-radius: 5px;
            padding: 24px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #3a78c2;
        }
        QLabel {
            color: #a9a9a9;
            font-weight: bold;
        }
        QTabWidget::pane {
            border: 1px solid #555;
            background: #2b2b2b;
        }
        QTabBar::tab {
            background: #3c3f41;
            color: #e0e0e0;
            padding: 12px;
            border-radius: 3px;
            margin: 2px;
        }
        QTabBar::tab:selected {
            background: #4a90e2;
            color: #ffffff;
        }
        QTabBar::tab:hover {
            background: #3a78c2;
        }
        QScrollBar:vertical, QScrollBar:horizontal {
            background: #2b2b2b;
        }
        QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
            background: #4a90e2;
            min-height: 20px;
            border-radius: 4px;
        }
        QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page {
            background: none;
        }
        """
        self.setStyleSheet(modern_stylesheet)

    def analyze(self):
        email_input = self.email_input.text().strip()
        link = self.link_input.text().strip()
        vt_api_key = get_virustotal_api_key()
        sb_api_key = get_safe_browsing_api_key()
        openai_api_key = get_openai_api_key()
        if not email_input and not link:
            QMessageBox.warning(self, "Input Error", "Please enter an email address or a link.")
            self.output_text.append("<i><span style='color:lightgrey;'>Skipping analysis because no input was provided.</span></i><br>")
            return
        self.output_text.clear()
        self.output_text.append("<br>Processing... Please wait.")
        self.thread = AnalyzerThread(email_input, link, vt_api_key, sb_api_key, openai_api_key)
        self.thread.output_signal.connect(self.append_output)
        self.thread.error_signal.connect(self.show_error)
        self.thread.start()

    def analyze_headers(self):
        headers_text = self.header_input.toPlainText()
        if not headers_text.strip():
            return
        self.header_output_text.clear()
        self.header_output_text.append("<br>Processing... Please wait.")
        self.header_thread = HeaderAnalyzerThread(headers_text)
        self.header_thread.output_signal.connect(self.append_header_output)
        self.header_thread.error_signal.connect(self.show_header_error)
        self.header_thread.start()

    def analyze_sentiment(self):
        content = self.sentiment_input.toPlainText()
        if not content.strip():
            self.sentiment_output_text.clear()
            return
        self.sentiment_output_text.clear()
        self.sentiment_output_text.append("<br>Processing... Please wait.")
        openai_api_key = get_openai_api_key()
        if not openai_api_key:
            QMessageBox.warning(self, "API Key Error", "OpenAI API key not provided in config.")
            self.sentiment_output_text.append("<i><span style='color:lightgrey;'>Skipping Sentiment Analysis because OpenAI API key is not provided.</span></i><br>")
            return
        self.sentiment_thread = SentimentAnalyzerThread(content, openai_api_key)
        self.sentiment_thread.output_signal.connect(self.append_sentiment_output)
        self.sentiment_thread.error_signal.connect(self.show_sentiment_error)
        self.sentiment_thread.start()

    def browse_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File for Analysis",
            "",
            "All Files (*);;Executable Files (*.exe);;PDF Files (*.pdf)",
            options=options
        )
        if file_path:
            self.attachment_path_input.setText(file_path)
            self.attachment_output_text.clear()
            self.attachment_output_text.append("<br>Processing... Please wait.")
            vt_api_key = get_virustotal_api_key()
            ha_api_key = get_hybrid_analysis_api_key()
            if not vt_api_key:
                QMessageBox.warning(self, "API Key Error", "VirusTotal API key not provided in config.")
                self.attachment_output_text.append("<i><span style='color:lightgrey;'>Skipping Attachment Analysis because VirusTotal API key is not provided.</span></i><br>")
                return
            if not ha_api_key:
                QMessageBox.warning(self, "API Key Error", "Hybrid Analysis API key not provided in config.")
                self.attachment_output_text.append("<i><span style='color:lightgrey;'>Skipping Hybrid Analysis because Hybrid Analysis API key is not provided.</span></i><br>")
            self.attachment_thread = AttachmentAnalyzerThread(file_path, vt_api_key, ha_api_key)
            self.attachment_thread.output_signal.connect(self.append_attachment_output)
            self.attachment_thread.error_signal.connect(self.show_attachment_error)
            self.attachment_thread.start()

    def search_file(self):
        file_path = self.attachment_path_input.text().strip().strip("'\"")
        if not file_path:
            QMessageBox.warning(self, "Input Error", "Please enter a file path.")
            return
        if not os.path.isfile(file_path):
            QMessageBox.warning(self, "File Error", "The specified file does not exist.")
            return
        self.attachment_output_text.clear()
        self.attachment_output_text.append("<br>Processing... Please wait.")
        vt_api_key = get_virustotal_api_key()
        ha_api_key = get_hybrid_analysis_api_key()
        if not vt_api_key:
            QMessageBox.warning(self, "API Key Error", "VirusTotal API key not provided in config.")
            self.attachment_output_text.append("<i><span style='color:lightgrey;'>Skipping Attachment Analysis because VirusTotal API key is not provided.</span></i><br>")
            return
        if not ha_api_key:
            QMessageBox.warning(self, "API Key Error", "Hybrid Analysis API key not provided in config.")
            self.attachment_output_text.append("<i><span style='color:lightgrey;'>Skipping Hybrid Analysis because Hybrid Analysis API key is not provided.</span></i><br>")
        self.attachment_thread = AttachmentAnalyzerThread(file_path, vt_api_key, ha_api_key)
        self.attachment_thread.output_signal.connect(self.append_attachment_output)
        self.attachment_thread.error_signal.connect(self.show_attachment_error)
        self.attachment_thread.start()

    def append_output(self, text):
        if "Processing... Please wait." in self.output_text.toPlainText():
            self.output_text.clear()
        self.output_text.append(text)

    def show_error(self, message):
        QMessageBox.warning(self, "Error", message)

    def append_header_output(self, text):
        if "Processing... Please wait." in self.header_output_text.toPlainText():
            self.header_output_text.clear()
        self.header_output_text.append(text)

    def show_header_error(self, message):
        QMessageBox.warning(self, "Error", "Invalid email headers. Please paste valid email header metadata.")
        self.header_output_text.append("<i><span style='color:lightgrey;'>Skipping Header Analysis due to an error.</span></i><br>")
        self.header_input.clear()

    def append_sentiment_output(self, text):
        if "Processing... Please wait." in self.sentiment_output_text.toPlainText():
            self.sentiment_output_text.clear()
        self.sentiment_output_text.append(text)

    def show_sentiment_error(self, message):
        QMessageBox.warning(self, "Error", f"Sentiment Analysis Error: {message}")
        self.sentiment_output_text.append("<i><span style='color:lightgrey;'>Skipping Sentiment Analysis due to an error.</span></i><br>")
        self.sentiment_input.clear()

    def append_attachment_output(self, text):
        if "Processing... Please wait." in self.attachment_output_text.toPlainText():
            self.attachment_output_text.clear()
        self.attachment_output_text.append(text)

    def show_attachment_error(self, message):
        QMessageBox.warning(self, "Error", f"Attachment Analysis Error: {message}")
        self.attachment_output_text.append("<i><span style='color:lightgrey;'>Skipping Attachment Analysis due to an error.</span></i><br>")
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
    icon_base64 = ""

    def __init__(self):
        super().__init__()

        pixmap = QPixmap()
        if self.icon_base64:
            pixmap.loadFromData(base64.b64decode(self.icon_base64))
        self.setWindowIcon(QIcon(pixmap))

        self.setWindowTitle("WhoDAT - InfoSec Analyzer for Nerds")
        self.resize(1000, 630)
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

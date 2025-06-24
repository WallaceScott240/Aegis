import sys
import socket
import threading
import requests
import paramiko
import os
import queue
import time
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout, 
                             QGroupBox, QLabel, QLineEdit, QPushButton, QTextEdit, QListWidget,
                             QFileDialog, QProgressBar, QMessageBox, QSplitter)
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# =====================
# CONSTANTS & CONFIG
# =====================
MAX_PORT_THREADS = 50
MAX_DIR_THREADS = 20
REQUEST_TIMEOUT = 5
SSH_TIMEOUT = 3

# =====================
# WORKER THREADS
# =====================
class PortScannerThread(QThread):
    update_signal = pyqtSignal(str, str)  # (message, color)
    result_signal = pyqtSignal(int, str)  # (port, banner)
    finished_signal = pyqtSignal(list)    # list of open ports

    def __init__(self, target, ports):
        super().__init__()
        self.target = target
        self.ports = ports
        self.running = True

    def run(self):
        port_queue = queue.Queue()
        open_ports = []
        
        for port in self.ports:
            port_queue.put(port)
            
        self.update_signal.emit(f"Scanning {len(self.ports)} ports on {self.target}", "info")
        
        threads = []
        for _ in range(min(MAX_PORT_THREADS, len(self.ports))):
            if not self.running:
                break
            t = threading.Thread(target=self.port_scan_worker, args=(port_queue, open_ports))
            t.daemon = True
            t.start()
            threads.append(t)
            
        port_queue.join()
        self.finished_signal.emit(open_ports)

    def port_scan_worker(self, port_queue, open_ports):
        while not port_queue.empty() and self.running:
            try:
                port = port_queue.get_nowait()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    if sock.connect_ex((self.target, port)) == 0:
                        open_ports.append(port)
                        try:
                            sock.send(b"GET / HTTP/1.1\r\n\r\n")
                            banner = sock.recv(1024).decode().strip()
                            self.result_signal.emit(port, banner[:100])
                        except:
                            self.result_signal.emit(port, "")
                port_queue.task_done()
            except queue.Empty:
                break
                
    def stop(self):
        self.running = False
        self.update_signal.emit("Port scan canceled", "warning")

class SSHBruteThread(QThread):
    update_signal = pyqtSignal(str, str)  # (message, color)
    result_signal = pyqtSignal(str, str)  # (status, password)
    finished_signal = pyqtSignal(bool)    # success or not

    def __init__(self, target, username, password_list):
        super().__init__()
        self.target = target
        self.username = username
        self.password_list = password_list
        self.running = True

    def run(self):
        self.update_signal.emit(f"Starting SSH brute-force on {self.target} with user '{self.username}'", "info")
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        success = False
        
        for password in self.password_list:
            if not self.running:
                break
                
            pwd = password.strip()
            try:
                ssh.connect(self.target, username=self.username, password=pwd, 
                           timeout=SSH_TIMEOUT, banner_timeout=30)
                self.result_signal.emit("success", pwd)
                success = True
                ssh.close()
                break
            except paramiko.AuthenticationException:
                self.result_signal.emit("failed", pwd)
            except Exception as e:
                self.result_signal.emit("error", str(e))
                break
                
        if not success:
            self.result_signal.emit("not_found", "")
        self.finished_signal.emit(success)
        
    def stop(self):
        self.running = False
        self.update_signal.emit("SSH brute-force canceled", "warning")

class DirEnumThread(QThread):
    update_signal = pyqtSignal(str, str)  # (message, color)
    result_signal = pyqtSignal(str)      # found URL
    finished_signal = pyqtSignal(int)    # number of found directories

    def __init__(self, target_url, wordlist):
        super().__init__()
        self.target_url = target_url
        self.wordlist = wordlist
        self.running = True

    def run(self):
        word_queue = queue.Queue()
        found_dirs = []
        
        for word in self.wordlist:
            word_queue.put(word)
            
        self.update_signal.emit(f"Enumerating {len(self.wordlist)} directories at {self.target_url}", "info")
        
        threads = []
        for _ in range(min(MAX_DIR_THREADS, len(self.wordlist))):
            if not self.running:
                break
            t = threading.Thread(target=self.dir_enum_worker, args=(word_queue, found_dirs))
            t.daemon = True
            t.start()
            threads.append(t)
            
        word_queue.join()
        self.finished_signal.emit(len(found_dirs))

    def dir_enum_worker(self, word_queue, found_dirs):
        while not word_queue.empty() and self.running:
            try:
                word = word_queue.get_nowait()
                url = f"{self.target_url}/{word.strip()}"
                try:
                    r = requests.get(url, timeout=REQUEST_TIMEOUT)
                    if r.status_code == 200:
                        found_dirs.append(url)
                        self.result_signal.emit(url)
                except requests.RequestException:
                    pass
                word_queue.task_done()
            except queue.Empty:
                break
                
    def stop(self):
        self.running = False
        self.update_signal.emit("Directory enumeration canceled", "warning")

class BannerGrabberThread(QThread):
    update_signal = pyqtSignal(str, str)  # (message, color)
    result_signal = pyqtSignal(str, str)  # (host:port, banner)

    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port

    def run(self):
        try:
            with socket.socket() as sock:
                sock.settimeout(2)
                sock.connect((self.host, self.port))
                sock.send(b"GET / HTTP/1.1\r\nHost: " + self.host.encode() + b"\r\n\r\n")
                banner = sock.recv(1024).decode().strip()
                self.result_signal.emit(f"{self.host}:{self.port}", banner)
        except Exception as e:
            self.result_signal.emit(f"{self.host}:{self.port}", f"Error: {str(e)}")

# =====================
# MAIN GUI APPLICATION
# =====================
class AegisApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Aegis - Greek Shield of Cybersecurity")
        self.setGeometry(100, 100, 900, 700)
        
        # Set dark theme
        self.set_dark_theme()
        
        # Create main layout
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        
        # Create tabs
        self.tabs = QTabWidget()
        self.port_scanner_tab = self.create_port_scanner_tab()
        self.ssh_brute_tab = self.create_ssh_brute_tab()
        self.dir_enum_tab = self.create_dir_enum_tab()
        self.banner_grabber_tab = self.create_banner_grabber_tab()
        
        self.tabs.addTab(self.port_scanner_tab, "Port Scanner")
        self.tabs.addTab(self.ssh_brute_tab, "SSH Brute Forcer")
        self.tabs.addTab(self.dir_enum_tab, "Directory Enumerator")
        self.tabs.addTab(self.banner_grabber_tab, "Banner Grabber")
        
        main_layout.addWidget(self.tabs)
        
        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
        
        self.setCentralWidget(main_widget)
        
        # Thread references
        self.port_scanner_thread = None
        self.ssh_brute_thread = None
        self.dir_enum_thread = None
        
    def set_dark_theme(self):
        # Set dark palette
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(45, 45, 45))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(45, 45, 45))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(45, 45, 45))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        QApplication.setPalette(dark_palette)
        
        # Set stylesheet
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2d2d2d;
            }
            QTabWidget::pane {
                border: 1px solid #444;
                background: #2d2d2d;
            }
            QTabBar::tab {
                background: #3a3a3a;
                color: white;
                padding: 8px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #4a4a4a;
                border-bottom-color: #6a6a6a;
            }
            QGroupBox {
                border: 1px solid #555;
                border-radius: 5px;
                margin-top: 1ex;
                font-weight: bold;
                color: #aaa;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 5px;
            }
            QTextEdit, QListWidget {
                background-color: #1e1e1e;
                color: #e0e0e0;
                border: 1px solid #444;
                border-radius: 3px;
            }
            QLineEdit {
                background-color: #1e1e1e;
                color: white;
                border: 1px solid #444;
                border-radius: 3px;
                padding: 5px;
            }
            QPushButton {
                background-color: #4a4a4a;
                color: white;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #5a5a5a;
            }
            QPushButton:pressed {
                background-color: #3a3a3a;
            }
            QPushButton:disabled {
                background-color: #333;
                color: #777;
            }
            QProgressBar {
                border: 1px solid #444;
                border-radius: 3px;
                text-align: center;
                background-color: #1e1e1e;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                width: 10px;
            }
        """)
    
    def create_port_scanner_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Input group
        input_group = QGroupBox("Scan Parameters")
        input_layout = QVBoxLayout(input_group)
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit("localhost")
        target_layout.addWidget(self.target_input)
        input_layout.addLayout(target_layout)
        
        # Ports input
        ports_layout = QHBoxLayout()
        ports_layout.addWidget(QLabel("Ports:"))
        self.ports_input = QLineEdit("21,22,80,443,8080")
        ports_layout.addWidget(self.ports_input)
        input_layout.addLayout(ports_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_port_scan)
        button_layout.addWidget(self.scan_button)
        
        self.stop_scan_button = QPushButton("Stop Scan")
        self.stop_scan_button.clicked.connect(self.stop_port_scan)
        self.stop_scan_button.setEnabled(False)
        button_layout.addWidget(self.stop_scan_button)
        
        input_layout.addLayout(button_layout)
        
        # Results
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout(results_group)
        
        # Splitter for results and details
        splitter = QSplitter(Qt.Horizontal)
        
        # Open ports list
        self.open_ports_list = QListWidget()
        self.open_ports_list.itemSelectionChanged.connect(self.show_port_details)
        splitter.addWidget(self.open_ports_list)
        
        # Banner details
        self.banner_text = QTextEdit()
        self.banner_text.setReadOnly(True)
        splitter.addWidget(self.banner_text)
        
        splitter.setSizes([200, 500])
        results_layout.addWidget(splitter)
        
        # Progress bar
        self.scan_progress = QProgressBar()
        results_layout.addWidget(self.scan_progress)
        
        # Status text
        self.scan_status = QTextEdit()
        self.scan_status.setReadOnly(True)
        self.scan_status.setMaximumHeight(80)
        results_layout.addWidget(self.scan_status)
        
        # Add groups to main layout
        layout.addWidget(input_group)
        layout.addWidget(results_group)
        
        return tab
        
    def create_ssh_brute_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Input group
        input_group = QGroupBox("SSH Parameters")
        input_layout = QVBoxLayout(input_group)
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        self.ssh_target_input = QLineEdit("localhost")
        target_layout.addWidget(self.ssh_target_input)
        input_layout.addLayout(target_layout)
        
        # Username input
        user_layout = QHBoxLayout()
        user_layout.addWidget(QLabel("Username:"))
        self.username_input = QLineEdit("root")
        user_layout.addWidget(self.username_input)
        input_layout.addLayout(user_layout)
        
        # Password file
        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel("Password File:"))
        self.pwd_file_input = QLineEdit()
        file_layout.addWidget(self.pwd_file_input)
        
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_password_file)
        file_layout.addWidget(browse_button)
        input_layout.addLayout(file_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.ssh_button = QPushButton("Start Brute Force")
        self.ssh_button.clicked.connect(self.start_ssh_brute)
        button_layout.addWidget(self.ssh_button)
        
        self.stop_ssh_button = QPushButton("Stop")
        self.stop_ssh_button.clicked.connect(self.stop_ssh_brute)
        self.stop_ssh_button.setEnabled(False)
        button_layout.addWidget(self.stop_ssh_button)
        
        input_layout.addLayout(button_layout)
        
        # Results
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout(results_group)
        
        # Attempts list
        self.attempts_list = QListWidget()
        results_layout.addWidget(self.attempts_list)
        
        # Status text
        self.ssh_status = QTextEdit()
        self.ssh_status.setReadOnly(True)
        self.ssh_status.setMaximumHeight(100)
        results_layout.addWidget(self.ssh_status)
        
        # Progress bar
        self.ssh_progress = QProgressBar()
        results_layout.addWidget(self.ssh_progress)
        
        # Add groups to main layout
        layout.addWidget(input_group)
        layout.addWidget(results_group)
        
        return tab
        
    def create_dir_enum_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Input group
        input_group = QGroupBox("Directory Enumeration")
        input_layout = QVBoxLayout(input_group)
        
        # URL input
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("Target URL:"))
        self.url_input = QLineEdit("http://localhost")
        url_layout.addWidget(self.url_input)
        input_layout.addLayout(url_layout)
        
        # Wordlist file
        wordlist_layout = QHBoxLayout()
        wordlist_layout.addWidget(QLabel("Wordlist File:"))
        self.wordlist_input = QLineEdit()
        wordlist_layout.addWidget(self.wordlist_input)
        
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_wordlist_file)
        wordlist_layout.addWidget(browse_button)
        input_layout.addLayout(wordlist_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.enum_button = QPushButton("Start Enumeration")
        self.enum_button.clicked.connect(self.start_dir_enum)
        button_layout.addWidget(self.enum_button)
        
        self.stop_enum_button = QPushButton("Stop")
        self.stop_enum_button.clicked.connect(self.stop_dir_enum)
        self.stop_enum_button.setEnabled(False)
        button_layout.addWidget(self.stop_enum_button)
        
        input_layout.addLayout(button_layout)
        
        # Results
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout(results_group)
        
        # Found directories list
        self.found_dirs_list = QListWidget()
        self.found_dirs_list.itemDoubleClicked.connect(self.open_url_in_browser)
        results_layout.addWidget(self.found_dirs_list)
        
        # Status text
        self.enum_status = QTextEdit()
        self.enum_status.setReadOnly(True)
        self.enum_status.setMaximumHeight(100)
        results_layout.addWidget(self.enum_status)
        
        # Progress bar
        self.enum_progress = QProgressBar()
        results_layout.addWidget(self.enum_progress)
        
        # Add groups to main layout
        layout.addWidget(input_group)
        layout.addWidget(results_group)
        
        return tab
        
    def create_banner_grabber_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Input group
        input_group = QGroupBox("Banner Grabber")
        input_layout = QVBoxLayout(input_group)
        
        # Host input
        host_layout = QHBoxLayout()
        host_layout.addWidget(QLabel("Host:"))
        self.banner_host_input = QLineEdit("localhost")
        host_layout.addWidget(self.banner_host_input)
        input_layout.addLayout(host_layout)
        
        # Port input
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Port:"))
        self.banner_port_input = QLineEdit("80")
        port_layout.addWidget(self.banner_port_input)
        input_layout.addLayout(port_layout)
        
        # Button
        self.grab_button = QPushButton("Grab Banner")
        self.grab_button.clicked.connect(self.grab_banner)
        input_layout.addWidget(self.grab_button)
        
        # Results
        results_group = QGroupBox("Banner Details")
        results_layout = QVBoxLayout(results_group)
        
        # Banner text
        self.banner_output = QTextEdit()
        self.banner_output.setReadOnly(True)
        results_layout.addWidget(self.banner_output)
        
        # Add groups to main layout
        layout.addWidget(input_group)
        layout.addWidget(results_group)
        
        return tab
        
    # =====================
    # PORT SCANNER METHODS
    # =====================
    def start_port_scan(self):
        target = self.target_input.text().strip()
        ports_text = self.ports_input.text().strip()
        
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target host")
            return
            
        try:
            ports = [int(p.strip()) for p in ports_text.split(",") if p.strip()]
        except ValueError:
            QMessageBox.warning(self, "Input Error", "Invalid port format. Use comma-separated numbers")
            return
            
        if not ports:
            QMessageBox.warning(self, "Input Error", "Please enter at least one port")
            return
            
        # Clear previous results
        self.open_ports_list.clear()
        self.banner_text.clear()
        self.scan_status.clear()
        self.scan_progress.setValue(0)
        self.scan_progress.setMaximum(len(ports))
        
        # Disable UI
        self.scan_button.setEnabled(False)
        self.stop_scan_button.setEnabled(True)
        
        # Start thread
        self.port_scanner_thread = PortScannerThread(target, ports)
        self.port_scanner_thread.update_signal.connect(self.update_scan_status)
        self.port_scanner_thread.result_signal.connect(self.add_open_port)
        self.port_scanner_thread.finished_signal.connect(self.port_scan_finished)
        self.port_scanner_thread.start()
        
    def stop_port_scan(self):
        if self.port_scanner_thread and self.port_scanner_thread.isRunning():
            self.port_scanner_thread.stop()
            self.port_scanner_thread.wait()
            self.scan_button.setEnabled(True)
            self.stop_scan_button.setEnabled(False)
        
    def update_scan_status(self, message, color):
        color_map = {
            "info": "cyan",
            "warning": "orange",
            "error": "red",
            "success": "lime"
        }
        
        html = f"<font color='{color_map.get(color, 'white')}'>[+] {message}</font><br>"
        current = self.scan_status.toHtml()
        self.scan_status.setHtml(current + html)
        self.scan_status.verticalScrollBar().setValue(self.scan_status.verticalScrollBar().maximum())
        
    def add_open_port(self, port, banner):
        item_text = f"Port {port} open"
        self.open_ports_list.addItem(item_text)
        self.port_details[port] = banner
        self.scan_progress.setValue(self.scan_progress.value() + 1)
        
    def show_port_details(self):
        selected_items = self.open_ports_list.selectedItems()
        if not selected_items:
            return
            
        port_text = selected_items[0].text()
        port = int(port_text.split()[1])
        banner = self.port_details.get(port, "No banner information")
        
        self.banner_text.setPlainText(banner)
        
    def port_scan_finished(self, open_ports):
        self.update_scan_status(f"Scan complete! Found {len(open_ports)} open ports", "info")
        self.scan_button.setEnabled(True)
        self.stop_scan_button.setEnabled(False)
        self.port_details = {}
        
    # =====================
    # SSH BRUTE METHODS
    # =====================
    def start_ssh_brute(self):
        target = self.ssh_target_input.text().strip()
        username = self.username_input.text().strip()
        pwd_file = self.pwd_file_input.text().strip()
        
        if not target or not username or not pwd_file:
            QMessageBox.warning(self, "Input Error", "Please fill all fields")
            return
            
        if not os.path.exists(pwd_file):
            QMessageBox.warning(self, "File Error", "Password file not found")
            return
            
        try:
            with open(pwd_file, 'r') as file:
                password_list = file.readlines()
        except Exception as e:
            QMessageBox.critical(self, "File Error", f"Error reading file: {str(e)}")
            return
            
        if not password_list:
            QMessageBox.warning(self, "File Error", "Password file is empty")
            return
            
        # Clear previous results
        self.attempts_list.clear()
        self.ssh_status.clear()
        self.ssh_progress.setValue(0)
        self.ssh_progress.setMaximum(len(password_list))
        
        # Disable UI
        self.ssh_button.setEnabled(False)
        self.stop_ssh_button.setEnabled(True)
        
        # Start thread
        self.ssh_brute_thread = SSHBruteThread(target, username, password_list)
        self.ssh_brute_thread.update_signal.connect(self.update_ssh_status)
        self.ssh_brute_thread.result_signal.connect(self.handle_ssh_result)
        self.ssh_brute_thread.finished_signal.connect(self.ssh_brute_finished)
        self.ssh_brute_thread.start()
        
    def stop_ssh_brute(self):
        if self.ssh_brute_thread and self.ssh_brute_thread.isRunning():
            self.ssh_brute_thread.stop()
            self.ssh_brute_thread.wait()
            self.ssh_button.setEnabled(True)
            self.stop_ssh_button.setEnabled(False)
        
    def update_ssh_status(self, message, color):
        color_map = {
            "info": "cyan",
            "warning": "orange",
            "error": "red",
            "success": "lime"
        }
        
        html = f"<font color='{color_map.get(color, 'white')}'>[+] {message}</font><br>"
        current = self.ssh_status.toHtml()
        self.ssh_status.setHtml(current + html)
        self.ssh_status.verticalScrollBar().setValue(self.ssh_status.verticalScrollBar().maximum())
        
    def handle_ssh_result(self, status, password):
        if status == "success":
            self.attempts_list.addItem(f"[SUCCESS] Password found: {password}")
            self.update_ssh_status(f"Password found: {password}", "success")
        elif status == "failed":
            self.attempts_list.addItem(f"[FAILED] {password}")
        elif status == "error":
            self.attempts_list.addItem(f"[ERROR] {password}")
            self.update_ssh_status(f"Error: {password}", "error")
        elif status == "not_found":
            self.attempts_list.addItem("[FAILED] Password not found in list")
            self.update_ssh_status("Password not found in list", "warning")
            
        self.ssh_progress.setValue(self.ssh_progress.value() + 1)
        
    def ssh_brute_finished(self, success):
        self.ssh_button.setEnabled(True)
        self.stop_ssh_button.setEnabled(False)
        if not success:
            self.update_ssh_status("Brute force attempt completed without success", "warning")
        
    # =====================
    # DIR ENUM METHODS
    # =====================
    def start_dir_enum(self):
        url = self.url_input.text().strip()
        wordlist_file = self.wordlist_input.text().strip()
        
        if not url or not wordlist_file:
            QMessageBox.warning(self, "Input Error", "Please fill all fields")
            return
            
        if not os.path.exists(wordlist_file):
            QMessageBox.warning(self, "File Error", "Wordlist file not found")
            return
            
        try:
            with open(wordlist_file, 'r') as file:
                wordlist = file.readlines()
        except Exception as e:
            QMessageBox.critical(self, "File Error", f"Error reading file: {str(e)}")
            return
            
        if not wordlist:
            QMessageBox.warning(self, "File Error", "Wordlist file is empty")
            return
            
        # Clear previous results
        self.found_dirs_list.clear()
        self.enum_status.clear()
        self.enum_progress.setValue(0)
        self.enum_progress.setMaximum(len(wordlist))
        
        # Disable UI
        self.enum_button.setEnabled(False)
        self.stop_enum_button.setEnabled(True)
        
        # Start thread
        self.dir_enum_thread = DirEnumThread(url, wordlist)
        self.dir_enum_thread.update_signal.connect(self.update_enum_status)
        self.dir_enum_thread.result_signal.connect(self.add_found_dir)
        self.dir_enum_thread.finished_signal.connect(self.dir_enum_finished)
        self.dir_enum_thread.start()
        
    def stop_dir_enum(self):
        if self.dir_enum_thread and self.dir_enum_thread.isRunning():
            self.dir_enum_thread.stop()
            self.dir_enum_thread.wait()
            self.enum_button.setEnabled(True)
            self.stop_enum_button.setEnabled(False)
        
    def update_enum_status(self, message, color):
        color_map = {
            "info": "cyan",
            "warning": "orange",
            "error": "red",
            "success": "lime"
        }
        
        html = f"<font color='{color_map.get(color, 'white')}'>[+] {message}</font><br>"
        current = self.enum_status.toHtml()
        self.enum_status.setHtml(current + html)
        self.enum_status.verticalScrollBar().setValue(self.enum_status.verticalScrollBar().maximum())
        
    def add_found_dir(self, url):
        self.found_dirs_list.addItem(url)
        self.enum_progress.setValue(self.enum_progress.value() + 1)
        
    def open_url_in_browser(self, item):
        url = item.text()
        import webbrowser
        webbrowser.open(url)
        
    def dir_enum_finished(self, found_count):
        self.update_enum_status(f"Enumeration complete! Found {found_count} directories", "info")
        self.enum_button.setEnabled(True)
        self.stop_enum_button.setEnabled(False)
        
    # =====================
    # BANNER GRABBER METHODS
    # =====================
    def grab_banner(self):
        host = self.banner_host_input.text().strip()
        port_text = self.banner_port_input.text().strip()
        
        if not host or not port_text:
            QMessageBox.warning(self, "Input Error", "Please fill all fields")
            return
            
        try:
            port = int(port_text)
        except ValueError:
            QMessageBox.warning(self, "Input Error", "Invalid port number")
            return
            
        # Clear previous results
        self.banner_output.clear()
        
        # Start thread
        self.banner_grabber_thread = BannerGrabberThread(host, port)
        self.banner_grabber_thread.result_signal.connect(self.show_banner_result)
        self.banner_grabber_thread.start()
        
    def show_banner_result(self, target, banner):
        self.banner_output.setPlainText(f"Banner for {target}:\n\n{banner}")
        
    # =====================
    # UTILITY METHODS
    # =====================
    def browse_password_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Password File", "", "Text Files (*.txt)")
        if file_path:
            self.pwd_file_input.setText(file_path)
            
    def browse_wordlist_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist File", "", "Text Files (*.txt)")
        if file_path:
            self.wordlist_input.setText(file_path)
            
    def closeEvent(self, event):
        # Stop any running threads
        if self.port_scanner_thread and self.port_scanner_thread.isRunning():
            self.port_scanner_thread.stop()
            self.port_scanner_thread.wait()
            
        if self.ssh_brute_thread and self.ssh_brute_thread.isRunning():
            self.ssh_brute_thread.stop()
            self.ssh_brute_thread.wait()
            
        if self.dir_enum_thread and self.dir_enum_thread.isRunning():
            self.dir_enum_thread.stop()
            self.dir_enum_thread.wait()
            
        event.accept()

# =====================
# APPLICATION START
# =====================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set application font
    font = QFont("Consolas", 10)
    app.setFont(font)
    
    window = AegisApp()
    window.show()
    sys.exit(app.exec_())
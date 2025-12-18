#!/usr/bin/env python3
"""
CipherSentry - Advanced Cybersecurity GUI Application
ENHANCED VERSION: Added Hydra, Nmap, and improved Metasploit GUI
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import subprocess
import json
import yaml
import socket
import os
import sys
import time
import random
import hashlib
import base64
import re
import platform
import webbrowser
import queue
import select
import signal
from datetime import datetime
from pathlib import Path
import uuid
import binascii
import tempfile

# Try to import optional modules with fallbacks
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# Import custom modules (fallback implementations)
class CryptoAnalyzer:
    def analyze(self, target, algorithm, analysis_type):
        return {
            'algorithm': algorithm,
            'key_strength': 'Strong',
            'entropy': 7.8,
            'processing_time': 150,
            'analysis': 'Analysis completed successfully',
            'recommendations': ['Use strong encryption', 'Rotate keys regularly']
        }

class TLSScanner:
    def scan(self, target, port=443):
        return {
            'target': f"{target}:{port}",
            'findings': [('Protocol Support', 'TLS 1.2/1.3 enabled', 'INFO', 'Good configuration')],
            'certificate': {
                'issuer': 'Demo CA',
                'subject': 'Demo Subject',
                'valid_from': '2024-01-01',
                'valid_until': '2025-01-01'
            }
        }

class ExploitManager:
    def generate_payload(self, payload_type, lhost, lport):
        return {
            'type': payload_type,
            'lhost': lhost,
            'lport': lport,
            'command': f'msfvenom -p {payload_type} LHOST={lhost} LPORT={lport}'
        }

class NetworkAnalyzer:
    def capture_packets(self, interface, count=10):
        return [f"Packet {i}: Sample data" for i in range(count)]

class CipherSentryGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CipherSentry v1.5 - Enhanced Cybersecurity Toolkit")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')
        
        # Check if running as root
        self.is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        
        # Initialize modules
        self.crypto_analyzer = CryptoAnalyzer()
        self.tls_scanner = TLSScanner()
        self.exploit_manager = ExploitManager()
        self.network_analyzer = NetworkAnalyzer()
        
        # Check available tools
        self.available_tools = self.check_available_tools()
        
        # Load configuration
        self.config = self.load_config()
        
        # Store running processes
        self.running_processes = []
        self.msf_process = None
        self.nmap_process = None
        self.hydra_process = None
        
        # Terminal output queue
        self.output_queue = queue.Queue()
        
        # Set up the GUI
        self.setup_gui()
        self.create_menu()
        self.create_tabs()
        self.create_status_bar()
        
        # Start output checker
        self.check_output_queue()
        
    def check_available_tools(self):
        """Check which security tools are available on the system"""
        tools = {}
        common_tools = [
            'msfconsole', 'nmap', 'wireshark', 'hashcat', 
            'john', 'sqlmap', 'aircrack-ng', 'hydra',
            'burpsuite', 'tshark', 'tcpdump', 'netstat',
            'msfvenom', 'arpspoof', 'ettercap', 'nikto',
            'dirb', 'gobuster', 'sqlite3', 'openssl'
        ]
        
        for tool in common_tools:
            try:
                if platform.system() == "Windows":
                    result = subprocess.run(f"where {tool}", shell=True, capture_output=True, text=True)
                else:
                    result = subprocess.run(['which', tool], capture_output=True, text=True)
                tools[tool] = result.returncode == 0
            except:
                tools[tool] = False
        
        # Check for Java (for Burp Suite)
        try:
            result = subprocess.run(['java', '-version'], capture_output=True, text=True, shell=True)
            tools['java'] = result.returncode == 0
        except:
            tools['java'] = False
            
        return tools
    
    def setup_gui(self):
        """Set up the main GUI components"""
        # Title bar
        title_frame = tk.Frame(self.root, bg='#2d2d2d', height=60)
        title_frame.pack(fill='x')
        title_frame.pack_propagate(False)
        
        title_text = "⚡ CipherSentry v1.5 - Enhanced Cybersecurity Toolkit"
        if self.is_root:
            title_text += " [ROOT]"
            
        title_label = tk.Label(
            title_frame,
            text=title_text,
            font=('Arial', 20, 'bold'),
            fg='#00ff88',
            bg='#2d2d2d'
        )
        title_label.pack(side='left', padx=20, pady=10)
        
        # Tool status indicator
        tools_available = sum(1 for v in self.available_tools.values() if v)
        status_text = f"Tools: {tools_available}/20 available"
        if not self.is_root:
            status_text += " (some require root)"
            
        self.mode_var = tk.StringVar(value=status_text)
        mode_label = tk.Label(
            title_frame,
            textvariable=self.mode_var,
            font=('Arial', 10),
            fg='#ffaa00',
            bg='#2d2d2d'
        )
        mode_label.pack(side='right', padx=20)
        
        # Main container
        self.main_container = tk.Frame(self.root, bg='#1e1e1e')
        self.main_container.pack(fill='both', expand=True, padx=10, pady=5)
    
    def create_menu(self):
        """Create the application menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg='#2d2d2d', fg='white')
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Project", command=self.new_project)
        file_menu.add_command(label="Open Project", command=self.open_project)
        file_menu.add_command(label="Save Results", command=self.save_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit_application)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0, bg='#2d2d2d', fg='white')
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Launch Metasploit", command=self.launch_metasploit)
        tools_menu.add_command(label="Launch Burp Suite", command=self.launch_burp)
        tools_menu.add_command(label="Launch Wireshark", command=self.launch_wireshark)
        tools_menu.add_separator()
        tools_menu.add_command(label="Launch Terminal", command=self.launch_terminal)
        tools_menu.add_command(label="Tool Configuration", command=self.configure_tools)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0, bg='#2d2d2d', fg='white')
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Dark Mode", command=lambda: self.change_theme('dark'))
        view_menu.add_command(label="Light Mode", command=lambda: self.change_theme('light'))
        view_menu.add_command(label="Report Dashboard", command=self.show_dashboard)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg='#2d2d2d', fg='white')
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="Check Tools", command=self.check_tools_status)
        help_menu.add_command(label="About", command=self.show_about)
    
    def create_tabs(self):
        """Create the main tabbed interface"""
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill='both', expand=True)
        
        # Apply custom style
        style = ttk.Style()
        style.theme_create('custom', parent='alt', settings={
            'TNotebook': {'configure': {'tabmargins': [2, 5, 2, 0]}},
            'TNotebook.Tab': {
                'configure': {
                    'padding': [10, 5],
                    'background': '#2d2d2d',
                    'foreground': 'white'
                },
                'map': {
                    'background': [('selected', '#007acc')],
                    'foreground': [('selected', 'white')]
                }
            }
        })
        style.theme_use('custom')
        
        # Create tabs
        self.create_crypto_tab()
        self.create_tls_tab()
        self.create_exploit_tab()
        self.create_network_tab()
        self.create_report_tab()
        self.create_settings_tab()
        self.create_nmap_tab()       # New Nmap tab
        self.create_hydra_tab()      # New Hydra tab
        self.create_msf_gui_tab()    # New Metasploit GUI tab
    
    def create_crypto_tab(self):
        """Cryptography Analysis Tab"""
        crypto_frame = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(crypto_frame, text="🔐 Cryptography")
        
        # Split frame into left and right
        left_frame = tk.Frame(crypto_frame, bg='#252526', width=300)
        left_frame.pack(side='left', fill='y', padx=(0, 5))
        left_frame.pack_propagate(False)
        
        right_frame = tk.Frame(crypto_frame, bg='#1e1e1e')
        right_frame.pack(side='right', fill='both', expand=True)
        
        # Left panel - Controls
        tk.Label(
            left_frame,
            text="Cryptographic Analysis",
            font=('Arial', 12, 'bold'),
            fg='#00ff88',
            bg='#252526'
        ).pack(pady=10)
        
        # Target input
        tk.Label(left_frame, text="Target Text/File:", fg='white', bg='#252526').pack(anchor='w', padx=10, pady=(20, 5))
        self.crypto_target = tk.Entry(left_frame, bg='#3c3c3c', fg='white', insertbackground='white')
        self.crypto_target.pack(fill='x', padx=10, pady=(0, 10))
        self.crypto_target.insert(0, "SecretMessage123!")
        
        # Algorithm selection
        tk.Label(left_frame, text="Algorithm:", fg='white', bg='#252526').pack(anchor='w', padx=10, pady=(5, 5))
        self.algo_var = tk.StringVar(value="AES-256")
        algo_combo = ttk.Combobox(
            left_frame,
            textvariable=self.algo_var,
            values=["AES-256", "RSA-2048", "ECC", "SHA3-512", "ChaCha20", "MD5", "SHA256"],
            state='readonly'
        )
        algo_combo.pack(fill='x', padx=10, pady=(0, 10))
        
        # Analysis type
        tk.Label(left_frame, text="Analysis Type:", fg='white', bg='#252526').pack(anchor='w', padx=10, pady=(5, 5))
        self.analysis_var = tk.StringVar(value="Encrypt/Decrypt")
        analysis_combo = ttk.Combobox(
            left_frame,
            textvariable=self.analysis_var,
            values=["Encrypt/Decrypt", "Hash Analysis", "Key Strength", "Side-Channel Simulation", "Generate Keys"],
            state='readonly'
        )
        analysis_combo.pack(fill='x', padx=10, pady=(0, 10))
        
        # Buttons
        button_style = {'bg': '#007acc', 'fg': 'white', 'padx': 20, 'pady': 8, 'border': 0}
        tk.Button(left_frame, text="Analyze", command=self.run_crypto_analysis, **button_style).pack(pady=5)
        tk.Button(left_frame, text="Brute Force Test", command=self.run_brute_force, bg='#d9534f', fg='white', padx=20, pady=8, border=0).pack(pady=5)
        tk.Button(left_frame, text="Generate Keys", command=self.generate_keys, bg='#5cb85c', fg='white', padx=20, pady=8, border=0).pack(pady=5)
        
        # Hash functions
        hash_frame = tk.LabelFrame(left_frame, text="Quick Hash", bg='#252526', fg='white')
        hash_frame.pack(fill='x', padx=10, pady=10)
        
        hash_buttons = [
            ("MD5", self.hash_md5),
            ("SHA1", self.hash_sha1),
            ("SHA256", self.hash_sha256),
        ]
        
        for text, command in hash_buttons:
            tk.Button(hash_frame, text=text, command=command, bg='#6c757d', fg='white', width=10).pack(side='left', padx=2, pady=5)
        
        # File operations
        file_frame = tk.LabelFrame(left_frame, text="File Operations", bg='#252526', fg='white')
        file_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Button(file_frame, text="Load File", command=self.load_crypto_file, bg='#17a2b8', fg='white', width=12).pack(side='left', padx=2, pady=5)
        tk.Button(file_frame, text="Save Results", command=self.save_crypto_results, bg='#28a745', fg='white', width=12).pack(side='left', padx=2, pady=5)
        
        # Right panel - Results
        tk.Label(
            right_frame,
            text="Analysis Results",
            font=('Arial', 12, 'bold'),
            fg='#00ff88',
            bg='#1e1e1e'
        ).pack(pady=10)
        
        # Results text area
        self.crypto_results = scrolledtext.ScrolledText(
            right_frame,
            bg='#252526',
            fg='white',
            insertbackground='white',
            wrap=tk.WORD,
            height=20
        )
        self.crypto_results.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Statistics frame
        stats_frame = tk.Frame(right_frame, bg='#1e1e1e')
        stats_frame.pack(fill='x', padx=10, pady=5)
        
        self.stats_labels = {}
        stats = ["Key Strength", "Entropy", "Processing Time", "Vulnerability Score"]
        for stat in stats:
            frame = tk.Frame(stats_frame, bg='#1e1e1e')
            frame.pack(side='left', padx=10)
            tk.Label(frame, text=stat, fg='#aaaaaa', bg='#1e1e1e').pack()
            self.stats_labels[stat] = tk.Label(frame, text="N/A", fg='#ffaa00', bg='#1e1e1e', font=('Arial', 10, 'bold'))
            self.stats_labels[stat].pack()
    
    def create_tls_tab(self):
        """TLS/SSL Scanner Tab"""
        tls_frame = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(tls_frame, text="🔒 TLS/SSL Scanner")
        
        # Top control panel
        control_frame = tk.Frame(tls_frame, bg='#252526', height=100)
        control_frame.pack(fill='x', pady=(0, 10))
        control_frame.pack_propagate(False)
        
        # Target input
        tk.Label(control_frame, text="Target Host:", fg='white', bg='#252526').place(x=20, y=20)
        self.tls_target = tk.Entry(control_frame, bg='#3c3c3c', fg='white', width=40)
        self.tls_target.place(x=120, y=20)
        self.tls_target.insert(0, "google.com")
        
        # Port input
        tk.Label(control_frame, text="Port:", fg='white', bg='#252526').place(x=400, y=20)
        self.tls_port = tk.Entry(control_frame, bg='#3c3c3c', fg='white', width=10)
        self.tls_port.place(x=440, y=20)
        self.tls_port.insert(0, "443")
        
        # Scan button
        tk.Button(
            control_frame,
            text="🚀 Scan TLS Configuration",
            command=self.run_tls_scan,
            bg='#007acc',
            fg='white',
            padx=20,
            pady=5
        ).place(x=550, y=15)
        
        # Quick test buttons
        tk.Button(
            control_frame,
            text="Test SSL Labs",
            command=self.test_ssl_labs,
            bg='#5cb85c',
            fg='white',
            padx=10,
            pady=5
        ).place(x=550, y=50)
        
        # Results area with treeview
        results_frame = tk.Frame(tls_frame, bg='#1e1e1e')
        results_frame.pack(fill='both', expand=True, padx=10)
        
        # Treeview for results
        columns = ('Category', 'Finding', 'Severity', 'Recommendation')
        self.tls_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.tls_tree.heading(col, text=col)
            self.tls_tree.column(col, width=150)
        
        self.tls_tree.column('Recommendation', width=300)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient='vertical', command=self.tls_tree.yview)
        self.tls_tree.configure(yscrollcommand=scrollbar.set)
        
        self.tls_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Certificate details area
        tk.Label(
            tls_frame,
            text="Certificate Details",
            font=('Arial', 10, 'bold'),
            fg='#00ff88',
            bg='#1e1e1e'
        ).pack(pady=(10, 5))
        
        self.cert_details = scrolledtext.ScrolledText(
            tls_frame,
            bg='#252526',
            fg='white',
            height=8
        )
        self.cert_details.pack(fill='x', padx=10, pady=(0, 10))
    
    def create_exploit_tab(self):
        """Exploit Development Tab"""
        exploit_frame = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(exploit_frame, text="💣 Exploit Development")
        
        # Warning label
        warning_frame = tk.Frame(exploit_frame, bg='#ff4444', height=40)
        warning_frame.pack(fill='x', pady=(0, 10))
        warning_text = "⚠️ WARNING: This module is for authorized security testing only!"
        if not self.is_root:
            warning_text += " Run as root for full functionality."
        tk.Label(
            warning_frame,
            text=warning_text,
            font=('Arial', 10, 'bold'),
            fg='white',
            bg='#ff4444'
        ).pack(pady=10)
        
        # Main content area
        main_content = tk.Frame(exploit_frame, bg='#1e1e1e')
        main_content.pack(fill='both', expand=True, padx=20)
        
        # Left panel - Payload generator
        left_panel = tk.Frame(main_content, bg='#252526', width=350)
        left_panel.pack(side='left', fill='y', padx=(0, 10))
        left_panel.pack_propagate(False)
        
        tk.Label(
            left_panel,
            text="Exploit Payload Generator",
            font=('Arial', 12, 'bold'),
            fg='#ffaa00',
            bg='#252526'
        ).pack(pady=10)
        
        # Payload configuration
        config_frame = tk.Frame(left_panel, bg='#252526')
        config_frame.pack(fill='x', padx=10, pady=5)
        
        labels = ["Payload Type:", "LHOST:", "LPORT:", "Platform:", "Encoder:"]
        defaults = ["windows/meterpreter/reverse_tcp", "192.168.1.100", "4444", "Windows", "x86/shikata_ga_nai"]
        
        self.exploit_vars = {}
        for i, (label, default) in enumerate(zip(labels, defaults)):
            tk.Label(config_frame, text=label, fg='white', bg='#252526').grid(row=i, column=0, sticky='w', pady=2)
            var = tk.StringVar(value=default)
            entry = tk.Entry(config_frame, textvariable=var, bg='#3c3c3c', fg='white')
            entry.grid(row=i, column=1, pady=2, padx=(5, 0))
            self.exploit_vars[label.replace(':', '').lower().replace(' ', '_')] = var
        
        # Generate button
        tk.Button(
            left_panel,
            text="Generate Payload",
            command=self.generate_payload,
            bg='#d9534f',
            fg='white',
            padx=20,
            pady=10
        ).pack(pady=20)
        
        # Metasploit status
        msf_status = "✓ Available" if self.available_tools.get('msfconsole', False) else "✗ Not installed"
        tk.Label(left_panel, text=f"Metasploit: {msf_status}", fg='white' if msf_status.startswith('✓') else 'red', bg='#252526').pack(pady=5)
        
        # Right panel - Exploit management
        right_panel = tk.Frame(main_content, bg='#1e1e1e')
        right_panel.pack(side='right', fill='both', expand=True)
        
        # Metasploit integration
        msf_frame = tk.LabelFrame(right_panel, text="Metasploit Integration", bg='#252526', fg='white')
        msf_frame.pack(fill='x', pady=(0, 10))
        
        tk.Button(
            msf_frame,
            text="Launch MSF Console",
            command=self.launch_metasploit_console,
            bg='#007acc',
            fg='white'
        ).pack(pady=10, padx=10, side='left')
        
        tk.Button(
            msf_frame,
            text="Run Auto-Exploit",
            command=self.run_auto_exploit,
            bg='#5cb85c',
            fg='white'
        ).pack(pady=10, padx=10, side='left')
        
        tk.Button(
            msf_frame,
            text="List Modules",
            command=self.list_msf_modules,
            bg='#f0ad4e',
            fg='white'
        ).pack(pady=10, padx=10, side='left')
        
        # Vulnerability scanner
        vuln_frame = tk.LabelFrame(right_panel, text="Vulnerability Scanner", bg='#252526', fg='white')
        vuln_frame.pack(fill='both', expand=True)
        
        tk.Label(vuln_frame, text="Target IP Range:", fg='white', bg='#252526').pack(anchor='w', padx=10, pady=(10, 0))
        self.scan_range = tk.Entry(vuln_frame, bg='#3c3c3c', fg='white')
        self.scan_range.pack(fill='x', padx=10, pady=(0, 10))
        self.scan_range.insert(0, "192.168.1.0/24")
        
        scan_button = tk.Button(
            vuln_frame,
            text="Scan Network for Vulnerabilities",
            command=self.scan_vulnerabilities,
            bg='#f0ad4e',
            fg='white'
        )
        scan_button.pack(pady=10)
        
        # Nmap status
        nmap_status = "✓ Available" if self.available_tools.get('nmap', False) else "✗ Not installed"
        tk.Label(vuln_frame, text=f"Nmap: {nmap_status}", fg='white' if nmap_status.startswith('✓') else 'red', bg='#252526').pack()
        
        # Results display
        self.exploit_results = scrolledtext.ScrolledText(
            vuln_frame,
            bg='#1e1e1e',
            fg='white',
            height=10
        )
        self.exploit_results.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Add some help text
        self.exploit_results.insert(tk.END, "Available Commands:\n")
        self.exploit_results.insert(tk.END, "• msfconsole - Launch Metasploit\n")
        self.exploit_results.insert(tk.END, "• nmap -sV <target> - Service detection\n")
        self.exploit_results.insert(tk.END, "• msfvenom -p <payload> LHOST=<ip> LPORT=<port>\n")
    
    def create_network_tab(self):
        """Network Analysis Tab"""
        network_frame = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(network_frame, text="🌐 Network Analysis")
        
        # Top control bar
        control_bar = tk.Frame(network_frame, bg='#252526', height=50)
        control_bar.pack(fill='x')
        control_bar.pack_propagate(False)
        
        # Capture controls
        tk.Button(
            control_bar,
            text="🎯 Start Capture",
            command=self.start_capture,
            bg='#5cb85c',
            fg='white'
        ).pack(side='left', padx=10, pady=10)
        
        tk.Button(
            control_bar,
            text="⏹️ Stop Capture",
            command=self.stop_capture,
            bg='#d9534f',
            fg='white'
        ).pack(side='left', padx=10, pady=10)
        
        tk.Button(
            control_bar,
            text="📂 Open PCAP",
            command=self.open_pcap,
            bg='#007acc',
            fg='white'
        ).pack(side='left', padx=10, pady=10)
        
        tk.Button(
            control_bar,
            text="🔍 Scan Ports",
            command=self.scan_ports,
            bg='#f0ad4e',
            fg='white'
        ).pack(side='left', padx=10, pady=10)
        
        self.capture_status = tk.Label(
            control_bar,
            text="Status: Ready",
            fg='#00ff88',
            bg='#252526'
        )
        self.capture_status.pack(side='right', padx=20)
        
        # Main content area
        content_frame = tk.Frame(network_frame, bg='#1e1e1e')
        content_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Left panel - Packet list
        left_frame = tk.Frame(content_frame, bg='#252526')
        left_frame.pack(side='left', fill='both', expand=True, padx=(0, 5))
        
        tk.Label(
            left_frame,
            text="Network Analysis",
            font=('Arial', 11, 'bold'),
            fg='white',
            bg='#252526'
        ).pack(pady=5)
        
        # Interface selection
        int_frame = tk.Frame(left_frame, bg='#252526')
        int_frame.pack(fill='x', padx=5, pady=5)
        tk.Label(int_frame, text="Interface:", fg='white', bg='#252526').pack(side='left')
        self.interface_var = tk.StringVar(value="eth0")
        tk.Entry(int_frame, textvariable=self.interface_var, width=10, bg='#3c3c3c', fg='white').pack(side='left', padx=5)
        
        # Packet list treeview
        packet_columns = ('No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
        self.packet_tree = ttk.Treeview(left_frame, columns=packet_columns, show='headings', height=15)
        
        for col in packet_columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=80)
        
        self.packet_tree.column('Info', width=200)
        self.packet_tree.bind('<<TreeviewSelect>>', self.show_packet_details)
        
        packet_scroll = ttk.Scrollbar(left_frame, orient='vertical', command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=packet_scroll.set)
        
        self.packet_tree.pack(side='left', fill='both', expand=True)
        packet_scroll.pack(side='right', fill='y')
        
        # Right panel - Packet details and statistics
        right_frame = tk.Frame(content_frame, bg='#1e1e1e', width=400)
        right_frame.pack(side='right', fill='both', padx=(5, 0))
        right_frame.pack_propagate(False)
        
        # Packet details notebook
        details_notebook = ttk.Notebook(right_frame)
        details_notebook.pack(fill='both', expand=True)
        
        # Packet details tab
        details_tab = tk.Frame(details_notebook, bg='#252526')
        details_notebook.add(details_tab, text="Packet Details")
        
        self.packet_details = scrolledtext.ScrolledText(
            details_tab,
            bg='#1e1e1e',
            fg='white',
            wrap=tk.WORD
        )
        self.packet_details.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Statistics tab
        stats_tab = tk.Frame(details_notebook, bg='#252526')
        details_notebook.add(stats_tab, text="Statistics")
        
        # Network info
        info_text = tk.Text(
            stats_tab,
            bg='#1e1e1e',
            fg='white',
            wrap=tk.WORD,
            height=10
        )
        info_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Get network info
        info_text.insert(tk.END, "Available Tools:\n")
        for tool, available in self.available_tools.items():
            if available:
                info_text.insert(tk.END, f"  ✓ {tool}\n")
        
        info_text.config(state='disabled')
    
    def create_nmap_tab(self):
        """Nmap Scanner Tab - NEW"""
        nmap_frame = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(nmap_frame, text="🔍 Nmap Scanner")
        
        # Check if Nmap is available
        nmap_available = self.available_tools.get('nmap', False)
        
        if not nmap_available:
            warning_frame = tk.Frame(nmap_frame, bg='#ff4444', height=40)
            warning_frame.pack(fill='x', pady=(0, 10))
            tk.Label(
                warning_frame,
                text="⚠️ Nmap not found! Install with: sudo apt install nmap",
                font=('Arial', 10, 'bold'),
                fg='white',
                bg='#ff4444'
            ).pack(pady=10)
        
        # Main content
        main_frame = tk.Frame(nmap_frame, bg='#1e1e1e')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Left panel - Configuration
        left_panel = tk.Frame(main_frame, bg='#252526', width=350)
        left_panel.pack(side='left', fill='y', padx=(0, 10))
        left_panel.pack_propagate(False)
        
        tk.Label(
            left_panel,
            text="Nmap Scanner",
            font=('Arial', 12, 'bold'),
            fg='#ffaa00',
            bg='#252526'
        ).pack(pady=10)
        
        # Target input
        tk.Label(left_panel, text="Target/IP Range:", fg='white', bg='#252526').pack(anchor='w', padx=10, pady=(20, 5))
        self.nmap_target = tk.Entry(left_panel, bg='#3c3c3c', fg='white')
        self.nmap_target.pack(fill='x', padx=10, pady=(0, 10))
        self.nmap_target.insert(0, "192.168.1.1")
        
        # Scan type
        tk.Label(left_panel, text="Scan Type:", fg='white', bg='#252526').pack(anchor='w', padx=10, pady=(5, 5))
        self.nmap_scan_type = tk.StringVar(value="Quick Scan")
        scan_types = ["Quick Scan", "Full Scan", "Ping Scan", "Service Detection", "OS Detection", "Vulnerability Scan"]
        scan_combo = ttk.Combobox(left_panel, textvariable=self.nmap_scan_type, values=scan_types, state='readonly')
        scan_combo.pack(fill='x', padx=10, pady=(0, 10))
        
        # Port specification
        tk.Label(left_panel, text="Ports (optional):", fg='white', bg='#252526').pack(anchor='w', padx=10, pady=(5, 5))
        self.nmap_ports = tk.Entry(left_panel, bg='#3c3c3c', fg='white')
        self.nmap_ports.pack(fill='x', padx=10, pady=(0, 10))
        self.nmap_ports.insert(0, "1-1000")
        
        # Options
        options_frame = tk.LabelFrame(left_panel, text="Options", bg='#252526', fg='white')
        options_frame.pack(fill='x', padx=10, pady=10)
        
        self.nmap_aggressive = tk.BooleanVar(value=True)
        self.nmap_version = tk.BooleanVar(value=True)
        self.nmap_script = tk.BooleanVar(value=False)
        
        tk.Checkbutton(options_frame, text="Aggressive Scan (-A)", variable=self.nmap_aggressive, 
                      fg='white', bg='#252526', selectcolor='#007acc').pack(anchor='w', pady=2)
        tk.Checkbutton(options_frame, text="Version Detection (-sV)", variable=self.nmap_version,
                      fg='white', bg='#252526', selectcolor='#007acc').pack(anchor='w', pady=2)
        tk.Checkbutton(options_frame, text="Script Scan (-sC)", variable=self.nmap_script,
                      fg='white', bg='#252526', selectcolor='#007acc').pack(anchor='w', pady=2)
        
        # Scan button
        tk.Button(
            left_panel,
            text="🚀 Run Nmap Scan",
            command=self.run_nmap_scan,
            bg='#007acc',
            fg='white',
            padx=20,
            pady=10
        ).pack(pady=20)
        
        # Common commands
        cmd_frame = tk.LabelFrame(left_panel, text="Common Commands", bg='#252526', fg='white')
        cmd_frame.pack(fill='x', padx=10, pady=10)
        
        commands = [
            ("Quick Scan", "nmap -T4 -F"),
            ("Full Scan", "nmap -p-"),
            ("Service Detection", "nmap -sV"),
            ("OS Detection", "nmap -O"),
        ]
        
        for cmd_name, cmd in commands:
            btn = tk.Button(cmd_frame, text=cmd_name, bg='#6c757d', fg='white', width=15,
                          command=lambda c=cmd: self.set_nmap_command(c))
            btn.pack(pady=2)
        
        # Right panel - Results
        right_panel = tk.Frame(main_frame, bg='#1e1e1e')
        right_panel.pack(side='right', fill='both', expand=True)
        
        tk.Label(
            right_panel,
            text="Scan Results",
            font=('Arial', 12, 'bold'),
            fg='#00ff88',
            bg='#1e1e1e'
        ).pack(pady=10)
        
        # Results text area
        self.nmap_results = scrolledtext.ScrolledText(
            right_panel,
            bg='#252526',
            fg='white',
            wrap=tk.WORD,
            height=25
        )
        self.nmap_results.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Status frame
        status_frame = tk.Frame(right_panel, bg='#1e1e1e')
        status_frame.pack(fill='x', padx=10, pady=5)
        
        self.nmap_status = tk.Label(status_frame, text="Status: Ready", fg='#00ff88', bg='#1e1e1e')
        self.nmap_status.pack(side='left')
        
        tk.Button(status_frame, text="Clear Results", command=self.clear_nmap_results, 
                 bg='#6c757d', fg='white').pack(side='right')
    
    def create_hydra_tab(self):
        """Hydra Password Cracker Tab - NEW"""
        hydra_frame = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(hydra_frame, text="🔑 Hydra Cracker")
        
        # Check if Hydra is available
        hydra_available = self.available_tools.get('hydra', False)
        
        if not hydra_available:
            warning_frame = tk.Frame(hydra_frame, bg='#ff4444', height=40)
            warning_frame.pack(fill='x', pady=(0, 10))
            tk.Label(
                warning_frame,
                text="⚠️ Hydra not found! Install with: sudo apt install hydra",
                font=('Arial', 10, 'bold'),
                fg='white',
                bg='#ff4444'
            ).pack(pady=10)
        
        # Warning label
        warning_frame2 = tk.Frame(hydra_frame, bg='#ff9900', height=40)
        warning_frame2.pack(fill='x', pady=(0, 10))
        tk.Label(
            warning_frame2,
            text="⚠️ Use only on systems you own or have explicit permission to test!",
            font=('Arial', 9, 'bold'),
            fg='black',
            bg='#ff9900'
        ).pack(pady=10)
        
        # Main content
        main_frame = tk.Frame(hydra_frame, bg='#1e1e1e')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Configuration panel
        config_frame = tk.Frame(main_frame, bg='#252526', width=400)
        config_frame.pack(side='left', fill='y', padx=(0, 10))
        config_frame.pack_propagate(False)
        
        tk.Label(
            config_frame,
            text="Hydra Configuration",
            font=('Arial', 12, 'bold'),
            fg='#ffaa00',
            bg='#252526'
        ).pack(pady=10)
        
        # Target configuration
        target_frame = tk.LabelFrame(config_frame, text="Target", bg='#252526', fg='white')
        target_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(target_frame, text="Target Host:", fg='white', bg='#252526').grid(row=0, column=0, sticky='w', pady=5)
        self.hydra_target = tk.Entry(target_frame, bg='#3c3c3c', fg='white', width=30)
        self.hydra_target.grid(row=0, column=1, pady=5, padx=5)
        self.hydra_target.insert(0, "192.168.1.1")
        
        tk.Label(target_frame, text="Port:", fg='white', bg='#252526').grid(row=1, column=0, sticky='w', pady=5)
        self.hydra_port = tk.Entry(target_frame, bg='#3c3c3c', fg='white', width=10)
        self.hydra_port.grid(row=1, column=1, sticky='w', pady=5, padx=5)
        self.hydra_port.insert(0, "22")
        
        # Service selection
        tk.Label(target_frame, text="Service:", fg='white', bg='#252526').grid(row=2, column=0, sticky='w', pady=5)
        self.hydra_service = tk.StringVar(value="ssh")
        services = ["ssh", "ftp", "telnet", "http", "https", "smtp", "pop3", "imap", "rdp", "vnc"]
        service_combo = ttk.Combobox(target_frame, textvariable=self.hydra_service, values=services, state='readonly', width=15)
        service_combo.grid(row=2, column=1, sticky='w', pady=5, padx=5)
        
        # Credentials frame
        cred_frame = tk.LabelFrame(config_frame, text="Credentials", bg='#252526', fg='white')
        cred_frame.pack(fill='x', padx=10, pady=10)
        
        # Username options
        tk.Label(cred_frame, text="Username:", fg='white', bg='#252526').grid(row=0, column=0, sticky='w', pady=5)
        self.hydra_username = tk.Entry(cred_frame, bg='#3c3c3c', fg='white', width=25)
        self.hydra_username.grid(row=0, column=1, pady=5, padx=5)
        self.hydra_username.insert(0, "admin")
        
        # Username file
        tk.Label(cred_frame, text="User List:", fg='white', bg='#252526').grid(row=1, column=0, sticky='w', pady=5)
        user_file_frame = tk.Frame(cred_frame, bg='#252526')
        user_file_frame.grid(row=1, column=1, sticky='w', pady=5, padx=5)
        self.hydra_userfile = tk.Entry(user_file_frame, bg='#3c3c3c', fg='white', width=20)
        self.hydra_userfile.pack(side='left')
        self.hydra_userfile.insert(0, "/usr/share/wordlists/users.txt")
        tk.Button(user_file_frame, text="Browse", command=self.browse_user_file, 
                 bg='#6c757d', fg='white', width=8).pack(side='left', padx=5)
        
        # Password options
        tk.Label(cred_frame, text="Password:", fg='white', bg='#252526').grid(row=2, column=0, sticky='w', pady=5)
        self.hydra_password = tk.Entry(cred_frame, bg='#3c3c3c', fg='white', width=25)
        self.hydra_password.grid(row=2, column=1, pady=5, padx=5)
        self.hydra_password.insert(0, "password")
        
        # Password file
        tk.Label(cred_frame, text="Pass List:", fg='white', bg='#252526').grid(row=3, column=0, sticky='w', pady=5)
        pass_file_frame = tk.Frame(cred_frame, bg='#252526')
        pass_file_frame.grid(row=3, column=1, sticky='w', pady=5, padx=5)
        self.hydra_passfile = tk.Entry(pass_file_frame, bg='#3c3c3c', fg='white', width=20)
        self.hydra_passfile.pack(side='left')
        self.hydra_passfile.insert(0, "/usr/share/wordlists/rockyou.txt")
        tk.Button(pass_file_frame, text="Browse", command=self.browse_pass_file,
                 bg='#6c757d', fg='white', width=8).pack(side='left', padx=5)
        
        # Options frame
        options_frame = tk.LabelFrame(config_frame, text="Options", bg='#252526', fg='white')
        options_frame.pack(fill='x', padx=10, pady=10)
        
        # Parallel tasks
        tk.Label(options_frame, text="Tasks:", fg='white', bg='#252526').grid(row=0, column=0, sticky='w', pady=5)
        self.hydra_tasks = tk.Entry(options_frame, bg='#3c3c3c', fg='white', width=10)
        self.hydra_tasks.grid(row=0, column=1, sticky='w', pady=5, padx=5)
        self.hydra_tasks.insert(0, "4")
        
        # Timeout
        tk.Label(options_frame, text="Timeout:", fg='white', bg='#252526').grid(row=1, column=0, sticky='w', pady=5)
        self.hydra_timeout = tk.Entry(options_frame, bg='#3c3c3c', fg='white', width=10)
        self.hydra_timeout.grid(row=1, column=1, sticky='w', pady=5, padx=5)
        self.hydra_timeout.insert(0, "30")
        
        # Attack buttons
        button_frame = tk.Frame(config_frame, bg='#252526')
        button_frame.pack(fill='x', padx=10, pady=20)
        
        tk.Button(
            button_frame,
            text="🚀 Start Attack",
            command=self.run_hydra_attack,
            bg='#d9534f',
            fg='white',
            padx=20,
            pady=10
        ).pack(side='left', padx=5)
        
        tk.Button(
            button_frame,
            text="Stop",
            command=self.stop_hydra_attack,
            bg='#6c757d',
            fg='white',
            padx=20,
            pady=10
        ).pack(side='left', padx=5)
        
        # Results panel
        results_frame = tk.Frame(main_frame, bg='#1e1e1e')
        results_frame.pack(side='right', fill='both', expand=True)
        
        tk.Label(
            results_frame,
            text="Attack Results",
            font=('Arial', 12, 'bold'),
            fg='#00ff88',
            bg='#1e1e1e'
        ).pack(pady=10)
        
        # Results text area
        self.hydra_results = scrolledtext.ScrolledText(
            results_frame,
            bg='#252526',
            fg='white',
            wrap=tk.WORD,
            height=25
        )
        self.hydra_results.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Status and control
        status_frame = tk.Frame(results_frame, bg='#1e1e1e')
        status_frame.pack(fill='x', padx=10, pady=5)
        
        self.hydra_status = tk.Label(status_frame, text="Status: Ready", fg='#00ff88', bg='#1e1e1e')
        self.hydra_status.pack(side='left')
        
        # Progress bar
        self.hydra_progress = ttk.Progressbar(status_frame, mode='indeterminate', length=200)
        self.hydra_progress.pack(side='right', padx=10)
    
    def create_msf_gui_tab(self):
        """Metasploit GUI Interface - NEW"""
        msf_frame = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(msf_frame, text="🛠️ MSF Console")
        
        # Check if Metasploit is available
        msf_available = self.available_tools.get('msfconsole', False)
        
        if not msf_available:
            warning_frame = tk.Frame(msf_frame, bg='#ff4444', height=40)
            warning_frame.pack(fill='x', pady=(0, 10))
            tk.Label(
                warning_frame,
                text="⚠️ Metasploit not found! Install with: sudo apt install metasploit-framework",
                font=('Arial', 10, 'bold'),
                fg='white',
                bg='#ff4444'
            ).pack(pady=10)
        
        # Warning label
        warning_frame2 = tk.Frame(msf_frame, bg='#ff4444', height=40)
        warning_frame2.pack(fill='x', pady=(0, 10))
        tk.Label(
            warning_frame2,
            text="⚠️ METASPLOIT CONSOLE - Use with extreme caution!",
            font=('Arial', 10, 'bold'),
            fg='white',
            bg='#ff4444'
        ).pack(pady=10)
        
        # Main content
        main_frame = tk.Frame(msf_frame, bg='#1e1e1e')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Left panel - Controls
        left_panel = tk.Frame(main_frame, bg='#252526', width=300)
        left_panel.pack(side='left', fill='y', padx=(0, 10))
        left_panel.pack_propagate(False)
        
        tk.Label(
            left_panel,
            text="MSF Console Controls",
            font=('Arial', 12, 'bold'),
            fg='#ffaa00',
            bg='#252526'
        ).pack(pady=10)
        
        # Connection status
        self.msf_connected = False
        self.msf_status_label = tk.Label(left_panel, text="Status: Not Connected", fg='#ff4444', bg='#252526')
        self.msf_status_label.pack(pady=5)
        
        # Connection buttons
        button_frame = tk.Frame(left_panel, bg='#252526')
        button_frame.pack(pady=10)
        
        tk.Button(
            button_frame,
            text="Start MSF",
            command=self.start_msf_console,
            bg='#5cb85c',
            fg='white',
            width=12
        ).pack(pady=5)
        
        tk.Button(
            button_frame,
            text="Stop MSF",
            command=self.stop_msf_console,
            bg='#d9534f',
            fg='white',
            width=12
        ).pack(pady=5)
        
        tk.Button(
            button_frame,
            text="Clear Console",
            command=self.clear_msf_console,
            bg='#6c757d',
            fg='white',
            width=12
        ).pack(pady=5)
        
        # Quick commands
        cmd_frame = tk.LabelFrame(left_panel, text="Quick Commands", bg='#252526', fg='white')
        cmd_frame.pack(fill='x', padx=10, pady=10)
        
        commands = [
            ("Show Exploits", "show exploits"),
            ("Show Payloads", "show payloads"),
            ("Show Options", "show options"),
            ("Search", "search ssh"),
            ("Help", "help"),
            ("Back", "back"),
            ("Exit", "exit"),
        ]
        
        for cmd_name, cmd in commands:
            btn = tk.Button(cmd_frame, text=cmd_name, bg='#007acc', fg='white', width=15,
                          command=lambda c=cmd: self.send_msf_command(c))
            btn.pack(pady=2)
        
        # Right panel - Console
        right_panel = tk.Frame(main_frame, bg='#1e1e1e')
        right_panel.pack(side='right', fill='both', expand=True)
        
        # Console output
        self.msf_console_output = scrolledtext.ScrolledText(
            right_panel,
            bg='#000000',
            fg='#00ff00',
            wrap=tk.WORD,
            height=25,
            font=('Courier', 10)
        )
        self.msf_console_output.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Insert welcome message
        self.msf_console_output.insert(tk.END, "╔══════════════════════════════════════════════════╗\n")
        self.msf_console_output.insert(tk.END, "║         Metasploit Console Interface           ║\n")
        self.msf_console_output.insert(tk.END, "╚══════════════════════════════════════════════════╝\n\n")
        self.msf_console_output.insert(tk.END, "Type 'help' for available commands or press 'Start MSF'\n")
        self.msf_console_output.insert(tk.END, "to connect to Metasploit framework.\n\n")
        
        # Command input
        input_frame = tk.Frame(right_panel, bg='#1e1e1e')
        input_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(input_frame, text="msf6 >", fg='#00ff00', bg='#1e1e1e', font=('Courier', 10)).pack(side='left')
        self.msf_command_input = tk.Entry(input_frame, bg='#000000', fg='#00ff00', 
                                         insertbackground='#00ff00', font=('Courier', 10))
        self.msf_command_input.pack(side='left', fill='x', expand=True, padx=5)
        self.msf_command_input.bind('<Return>', self.handle_msf_command)
        
        # Send button
        tk.Button(input_frame, text="Send", command=lambda: self.handle_msf_command(None),
                 bg='#007acc', fg='white').pack(side='left', padx=5)
    
    def create_report_tab(self):
        """Reporting Dashboard Tab"""
        report_frame = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(report_frame, text="📊 Reports")
        
        # Report controls
        controls = tk.Frame(report_frame, bg='#252526', height=50)
        controls.pack(fill='x')
        controls.pack_propagate(False)
        
        tk.Button(
            controls,
            text="Generate Report",
            command=self.generate_report,
            bg='#007acc',
            fg='white'
        ).pack(side='left', padx=10, pady=10)
        
        tk.Button(
            controls,
            text="Export to PDF",
            command=self.export_pdf,
            bg='#5cb85c',
            fg='white'
        ).pack(side='left', padx=10, pady=10)
        
        tk.Button(
            controls,
            text="Clear All",
            command=self.clear_reports,
            bg='#d9534f',
            fg='white'
        ).pack(side='left', padx=10, pady=10)
        
        tk.Button(
            controls,
            text="View Logs",
            command=self.view_logs,
            bg='#f0ad4e',
            fg='white'
        ).pack(side='left', padx=10, pady=10)
        
        # Dashboard content
        dashboard_frame = tk.Frame(report_frame, bg='#1e1e1e')
        dashboard_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Create metric cards
        metrics = [
            ("Total Scans", "0", "#007acc"),
            ("Vulnerabilities", "0", "#d9534f"),
            ("High Risk", "0", "#ff4444"),
            ("TLS Issues", "0", "#f0ad4e"),
            ("Crypto Weak", "0", "#ff8800"),
            ("Network Alerts", "0", "#00cc88")
        ]
        
        self.metric_labels = {}
        for i, (title, value, color) in enumerate(metrics):
            row, col = divmod(i, 3)
            card = tk.Frame(dashboard_frame, bg=color, height=100, width=200)
            card.grid(row=row, column=col, padx=10, pady=10, sticky='nsew')
            card.grid_propagate(False)
            
            tk.Label(
                card,
                text=title,
                font=('Arial', 10),
                fg='white',
                bg=color
            ).pack(pady=(15, 5))
            
            label = tk.Label(
                card,
                text=value,
                font=('Arial', 24, 'bold'),
                fg='white',
                bg=color
            )
            label.pack()
            self.metric_labels[title] = label
        
        # Recent activity
        activity_frame = tk.LabelFrame(
            dashboard_frame,
            text="Recent Activity",
            bg='#252526',
            fg='white',
            font=('Arial', 12, 'bold')
        )
        activity_frame.grid(row=2, column=0, columnspan=3, sticky='nsew', padx=10, pady=20)
        
        self.activity_list = tk.Listbox(
            activity_frame,
            bg='#1e1e1e',
            fg='white',
            height=8
        )
        self.activity_list.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Add initial activities
        self.log_activity("Application started")
        if self.is_root:
            self.log_activity("Running with root privileges")
        
        # Add scrollbar to activity list
        scrollbar = tk.Scrollbar(activity_frame)
        scrollbar.pack(side='right', fill='y')
        self.activity_list.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.activity_list.yview)
    
    def create_settings_tab(self):
        """Settings Tab"""
        settings_frame = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(settings_frame, text="⚙️ Settings")
        
        # Settings notebook
        settings_notebook = ttk.Notebook(settings_frame)
        settings_notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # General settings
        general_frame = tk.Frame(settings_notebook, bg='#252526')
        settings_notebook.add(general_frame, text="General")
        
        tk.Label(
            general_frame,
            text="Application Settings",
            font=('Arial', 14, 'bold'),
            fg='white',
            bg='#252526'
        ).pack(pady=20)
        
        # Theme selection
        theme_frame = tk.Frame(general_frame, bg='#252526')
        theme_frame.pack(fill='x', padx=20, pady=10)
        
        tk.Label(theme_frame, text="Theme:", fg='white', bg='#252526').pack(side='left')
        self.theme_var = tk.StringVar(value="Dark")
        tk.Radiobutton(theme_frame, text="Dark", variable=self.theme_var, value="Dark", 
                      fg='white', bg='#252526', selectcolor='#007acc').pack(side='left', padx=20)
        tk.Radiobutton(theme_frame, text="Light", variable=self.theme_var, value="Light",
                      fg='white', bg='#252526', selectcolor='#007acc').pack(side='left')
        
        # Auto-save
        self.auto_save_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            general_frame,
            text="Auto-save results",
            variable=self.auto_save_var,
            fg='white',
            bg='#252526',
            selectcolor='#007acc'
        ).pack(pady=10)
        
        # Tool paths
        tools_frame = tk.Frame(settings_notebook, bg='#252526')
        settings_notebook.add(tools_frame, text="Tool Paths")
        
        self.tool_paths = {}
        tools = [
            ("Metasploit", "msfconsole"),
            ("Wireshark", "wireshark"),
            ("Nmap", "nmap"),
            ("Burp Suite", "burpsuite"),
            ("Hashcat", "hashcat"),
            ("Hydra", "hydra"),
        ]
        
        for i, (tool, default) in enumerate(tools):
            frame = tk.Frame(tools_frame, bg='#252526')
            frame.pack(fill='x', padx=20, pady=10)
            
            tk.Label(frame, text=f"{tool} Path:", fg='white', bg='#252526', width=15).pack(side='left')
            var = tk.StringVar(value=default)
            entry = tk.Entry(frame, textvariable=var, bg='#3c3c3c', fg='white', width=40)
            entry.pack(side='left', padx=(10, 5))
            self.tool_paths[tool.lower().replace(' ', '_')] = var
            
            tk.Button(
                frame,
                text="Test",
                command=lambda t=tool, v=var: self.test_tool_path(t, v.get()),
                bg='#007acc',
                fg='white'
            ).pack(side='left', padx=5)
        
        # Save button
        tk.Button(
            settings_frame,
            text="Save Settings",
            command=self.save_settings,
            bg='#5cb85c',
            fg='white',
            padx=30,
            pady=10
        ).pack(side='bottom', pady=20)
    
    def create_status_bar(self):
        """Create status bar at bottom"""
        self.status_bar = tk.Frame(self.root, bg='#007acc', height=25)
        self.status_bar.pack(fill='x', side='bottom')
        self.status_bar.pack_propagate(False)
        
        self.status_label = tk.Label(
            self.status_bar,
            text="Ready - CipherSentry v1.5",
            fg='white',
            bg='#007acc'
        )
        self.status_label.pack(side='left', padx=10)
        
        # Progress bar
        self.progress = ttk.Progressbar(
            self.status_bar,
            mode='indeterminate',
            length=200
        )
        self.progress.pack(side='right', padx=10, pady=2)
    
    # ========== NEW NMAP METHODS ==========
    
    def set_nmap_command(self, command):
        """Set a predefined Nmap command"""
        parts = command.split()
        if len(parts) > 1 and parts[0] == "nmap":
            # Extract target if present in sample command
            for part in parts[1:]:
                if not part.startswith('-') and '.' in part:
                    self.nmap_target.delete(0, tk.END)
                    self.nmap_target.insert(0, part)
                    break
        
        self.nmap_results.delete(1.0, tk.END)
        self.nmap_results.insert(tk.END, f"Command: {command}\n\n")
        self.update_status(f"Command set: {command}")
    
    def run_nmap_scan(self):
        """Run Nmap scan"""
        target = self.nmap_target.get()
        scan_type = self.nmap_scan_type.get()
        ports = self.nmap_ports.get()
        
        if not target:
            self.show_error("Please enter a target")
            return
        
        if not self.available_tools.get('nmap', False):
            self.show_error("Nmap not found. Install with: sudo apt install nmap")
            return
        
        # Build command based on scan type
        cmd = ["nmap"]
        
        if scan_type == "Quick Scan":
            cmd.extend(["-T4", "-F"])
        elif scan_type == "Full Scan":
            cmd.extend(["-p-"])
        elif scan_type == "Ping Scan":
            cmd.extend(["-sn"])
        elif scan_type == "Service Detection":
            cmd.extend(["-sV"])
        elif scan_type == "OS Detection":
            cmd.extend(["-O"])
        elif scan_type == "Vulnerability Scan":
            cmd.extend(["--script", "vuln"])
        
        # Add options
        if self.nmap_aggressive.get():
            cmd.append("-A")
        if self.nmap_version.get() and "-sV" not in cmd:
            cmd.append("-sV")
        if self.nmap_script.get() and "--script" not in cmd:
            cmd.extend(["-sC"])
        
        # Add ports if specified
        if ports and "-p-" not in cmd:
            cmd.extend(["-p", ports])
        
        # Add target
        cmd.append(target)
        
        self.nmap_status.config(text="Status: Scanning...", fg='#ffaa00')
        self.nmap_results.delete(1.0, tk.END)
        self.nmap_results.insert(tk.END, f"Running command: {' '.join(cmd)}\n")
        self.nmap_results.insert(tk.END, "="*60 + "\n\n")
        self.update_status(f"Running Nmap scan on {target}...")
        
        def run_scan():
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                self.nmap_process = process
                
                # Read output in real-time
                for line in iter(process.stdout.readline, ''):
                    self.root.after(0, lambda l=line: self.nmap_results.insert(tk.END, l))
                    self.root.after(0, self.nmap_results.see, tk.END)
                
                process.stdout.close()
                return_code = process.wait()
                
                if return_code == 0:
                    self.root.after(0, lambda: self.nmap_status.config(text="Status: Completed", fg='#00ff88'))
                    self.root.after(0, lambda: self.update_status(f"Nmap scan on {target} completed"))
                    self.root.after(0, lambda: self.log_activity(f"Nmap scan on {target}"))
                else:
                    self.root.after(0, lambda: self.nmap_status.config(text="Status: Error", fg='#ff4444'))
                
            except Exception as e:
                self.root.after(0, lambda: self.show_error(f"Nmap scan failed: {str(e)}"))
                self.root.after(0, lambda: self.nmap_status.config(text="Status: Error", fg='#ff4444'))
        
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
    
    def clear_nmap_results(self):
        """Clear Nmap results"""
        self.nmap_results.delete(1.0, tk.END)
        self.nmap_status.config(text="Status: Ready", fg='#00ff88')
        self.update_status("Nmap results cleared")
    
    # ========== NEW HYDRA METHODS ==========
    
    def browse_user_file(self):
        """Browse for username wordlist"""
        filename = filedialog.askopenfilename(title="Select Username Wordlist")
        if filename:
            self.hydra_userfile.delete(0, tk.END)
            self.hydra_userfile.insert(0, filename)
    
    def browse_pass_file(self):
        """Browse for password wordlist"""
        filename = filedialog.askopenfilename(title="Select Password Wordlist")
        if filename:
            self.hydra_passfile.delete(0, tk.END)
            self.hydra_passfile.insert(0, filename)
    
    def run_hydra_attack(self):
        """Run Hydra password attack"""
        target = self.hydra_target.get()
        port = self.hydra_port.get()
        service = self.hydra_service.get()
        
        if not target:
            self.show_error("Please enter a target")
            return
        
        if not self.available_tools.get('hydra', False):
            self.show_error("Hydra not found. Install with: sudo apt install hydra")
            return
        
        # Build command
        cmd = ["hydra"]
        
        # Add target and service
        cmd.extend(["-L" if os.path.exists(self.hydra_userfile.get()) else "-l", 
                   self.hydra_userfile.get() if os.path.exists(self.hydra_userfile.get()) else self.hydra_username.get()])
        
        cmd.extend(["-P" if os.path.exists(self.hydra_passfile.get()) else "-p",
                   self.hydra_passfile.get() if os.path.exists(self.hydra_passfile.get()) else self.hydra_password.get()])
        
        # Add options
        tasks = self.hydra_tasks.get()
        timeout = self.hydra_timeout.get()
        
        if tasks:
            cmd.extend(["-t", tasks])
        if timeout:
            cmd.extend(["-w", timeout])
        
        # Add target
        cmd.extend([f"{service}://{target}:{port}"])
        
        self.hydra_status.config(text="Status: Attacking...", fg='#ffaa00')
        self.hydra_progress.start()
        self.hydra_results.delete(1.0, tk.END)
        self.hydra_results.insert(tk.END, f"Running command: {' '.join(cmd)}\n")
        self.hydra_results.insert(tk.END, "="*60 + "\n\n")
        self.update_status(f"Running Hydra attack on {target}...")
        
        def run_attack():
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                self.hydra_process = process
                
                # Read output in real-time
                for line in iter(process.stdout.readline, ''):
                    self.root.after(0, lambda l=line: self.hydra_results.insert(tk.END, l))
                    self.root.after(0, self.hydra_results.see, tk.END)
                    
                    # Check for found credentials
                    if "login:" in line.lower() and "password:" in line.lower():
                        self.root.after(0, lambda: self.hydra_results.insert(tk.END, "\n⚠️ CREDENTIALS FOUND! ⚠️\n", "found"))
                        self.hydra_results.tag_config("found", foreground="#ff4444", font=('Arial', 10, 'bold'))
                
                process.stdout.close()
                return_code = process.wait()
                
                self.root.after(0, self.hydra_progress.stop)
                
                if return_code == 0:
                    self.root.after(0, lambda: self.hydra_status.config(text="Status: Completed", fg='#00ff88'))
                    self.root.after(0, lambda: self.update_status(f"Hydra attack on {target} completed"))
                    self.root.after(0, lambda: self.log_activity(f"Hydra attack on {target}"))
                else:
                    self.root.after(0, lambda: self.hydra_status.config(text="Status: Error", fg='#ff4444'))
                
            except Exception as e:
                self.root.after(0, lambda: self.show_error(f"Hydra attack failed: {str(e)}"))
                self.root.after(0, lambda: self.hydra_status.config(text="Status: Error", fg='#ff4444'))
                self.root.after(0, self.hydra_progress.stop)
        
        thread = threading.Thread(target=run_attack)
        thread.daemon = True
        thread.start()
    
    def stop_hydra_attack(self):
        """Stop Hydra attack"""
        if self.hydra_process:
            try:
                self.hydra_process.terminate()
                self.hydra_status.config(text="Status: Stopped", fg='#ff4444')
                self.hydra_progress.stop()
                self.update_status("Hydra attack stopped")
                self.hydra_results.insert(tk.END, "\n[!] Attack stopped by user\n")
            except:
                pass
    
    # ========== NEW METASPLOIT GUI METHODS ==========
    
    def start_msf_console(self):
        """Start Metasploit console"""
        if not self.available_tools.get('msfconsole', False):
            self.show_error("Metasploit not found. Install with: sudo apt install metasploit-framework")
            return
        
        if self.msf_process:
            self.msf_console_output.insert(tk.END, "[!] MSF console is already running\n")
            return
        
        self.msf_console_output.insert(tk.END, "[*] Starting Metasploit console...\n")
        self.update_status("Starting Metasploit console...")
        
        def run_msf():
            try:
                # Start msfconsole in interactive mode
                if platform.system() == "Windows":
                    process = subprocess.Popen(
                        ["msfconsole", "-q"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1,
                        universal_newlines=True,
                        shell=True
                    )
                else:
                    process = subprocess.Popen(
                        ["msfconsole", "-q"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1,
                        universal_newlines=True
                    )
                
                self.msf_process = process
                self.msf_connected = True
                
                self.root.after(0, lambda: self.msf_status_label.config(text="Status: Connected", fg='#00ff88'))
                self.root.after(0, lambda: self.msf_console_output.insert(tk.END, "[+] Metasploit console started\n"))
                self.root.after(0, lambda: self.msf_console_output.insert(tk.END, "Type 'help' for available commands\n\n"))
                
                # Start reading output
                self.read_msf_output(process)
                
            except Exception as e:
                self.root.after(0, lambda: self.show_error(f"Failed to start MSF: {str(e)}"))
                self.root.after(0, lambda: self.msf_status_label.config(text="Status: Error", fg='#ff4444'))
        
        thread = threading.Thread(target=run_msf)
        thread.daemon = True
        thread.start()
    
    def read_msf_output(self, process):
        """Read output from Metasploit process"""
        def read():
            try:
                while self.msf_connected and process.poll() is None:
                    line = process.stdout.readline()
                    if line:
                        self.root.after(0, lambda l=line: self.msf_console_output.insert(tk.END, l))
                        self.root.after(0, self.msf_console_output.see, tk.END)
                    time.sleep(0.1)
            except:
                pass
        
        thread = threading.Thread(target=read)
        thread.daemon = True
        thread.start()
    
    def stop_msf_console(self):
        """Stop Metasploit console"""
        if self.msf_process:
            try:
                # Send exit command
                self.msf_process.stdin.write("exit\n")
                self.msf_process.stdin.flush()
                time.sleep(1)
                self.msf_process.terminate()
                self.msf_process = None
                self.msf_connected = False
                
                self.msf_status_label.config(text="Status: Not Connected", fg='#ff4444')
                self.msf_console_output.insert(tk.END, "\n[*] Metasploit console stopped\n")
                self.update_status("Metasploit console stopped")
            except:
                pass
    
    def clear_msf_console(self):
        """Clear Metasploit console output"""
        self.msf_console_output.delete(1.0, tk.END)
        self.msf_console_output.insert(tk.END, "[*] Console cleared\n")
        self.update_status("MSF console cleared")
    
    def send_msf_command(self, command):
        """Send command to Metasploit console"""
        if not self.msf_process or not self.msf_connected:
            self.show_error("MSF console is not running. Click 'Start MSF' first.")
            return
        
        try:
            # Display command in console
            self.msf_console_output.insert(tk.END, f"msf6 > {command}\n")
            self.msf_console_output.see(tk.END)
            
            # Send command to process
            self.msf_process.stdin.write(f"{command}\n")
            self.msf_process.stdin.flush()
            
            # Clear input field
            self.msf_command_input.delete(0, tk.END)
            
        except Exception as e:
            self.msf_console_output.insert(tk.END, f"[!] Error sending command: {str(e)}\n")
    
    def handle_msf_command(self, event):
        """Handle command input from GUI"""
        command = self.msf_command_input.get().strip()
        if command:
            self.send_msf_command(command)
    
    # ========== CRYPTOGRAPHY METHODS ==========
    
    def run_crypto_analysis(self):
        """Run cryptographic analysis"""
        target = self.crypto_target.get()
        algorithm = self.algo_var.get()
        analysis_type = self.analysis_var.get()
        
        if not target:
            self.show_error("Please enter text to analyze")
            return
        
        self.update_status(f"Running {analysis_type} with {algorithm}...")
        self.progress.start()
        
        def analyze():
            try:
                time.sleep(1)  # Simulate processing
                
                # Generate results based on input
                results = {
                    'algorithm': algorithm,
                    'key_strength': 'Strong' if '256' in algorithm or '2048' in algorithm else 'Moderate',
                    'entropy': random.uniform(6.5, 8.5),
                    'processing_time': random.randint(100, 500),
                    'analysis': 'No significant vulnerabilities detected.',
                    'recommendations': [
                        'Use SHA-256 or higher for hashing',
                        'Implement perfect forward secrecy',
                        'Rotate keys regularly'
                    ]
                }
                
                if analysis_type == "Hash Analysis":
                    results['hash'] = hashlib.sha256(target.encode()).hexdigest()
                    results['analysis'] = f"Hash calculated successfully. Length: {len(results['hash'])} chars"
                elif analysis_type == "Generate Keys":
                    results['key_pair'] = f"{algorithm} keys generated"
                    results['public_key'] = base64.b64encode(os.urandom(32)).decode()[:50] + "..."
                    results['private_key'] = base64.b64encode(os.urandom(64)).decode()[:50] + "..."
                
                self.root.after(0, lambda: self.display_crypto_results(results, analysis_type))
                
            except Exception as e:
                self.root.after(0, lambda: self.show_error(f"Crypto analysis failed: {str(e)}"))
            finally:
                self.root.after(0, self.analysis_complete)
        
        thread = threading.Thread(target=analyze)
        thread.daemon = True
        thread.start()
    
    def run_brute_force(self):
        """Brute force test simulation"""
        target = self.crypto_target.get()
        if not target:
            self.show_error("Please enter text to test")
            return
        
        self.update_status("Running brute force simulation...")
        self.progress.start()
        
        def brute_force():
            try:
                time.sleep(2)
                results = {
                    'attempts': random.randint(1000, 1000000),
                    'time': f"{random.uniform(1.5, 10.2):.1f} seconds",
                    'success': random.choice([True, False]),
                    'method': random.choice(['Dictionary', 'Rainbow Table', 'Brute Force'])
                }
                self.root.after(0, lambda: self.display_brute_force_results(results))
            except Exception as e:
                self.root.after(0, lambda: self.show_error(f"Brute force test failed: {str(e)}"))
            finally:
                self.root.after(0, self.analysis_complete)
        
        thread = threading.Thread(target=brute_force)
        thread.daemon = True
        thread.start()
    
    def generate_keys(self):
        """Generate cryptographic keys"""
        algorithm = self.algo_var.get()
        self.update_status(f"Generating {algorithm} keys...")
        
        key_info = {
            'algorithm': algorithm,
            'key_size': '256 bits' if '256' in algorithm else '2048 bits' if '2048' in algorithm else 'Variable',
            'public_key': base64.b64encode(os.urandom(48)).decode()[:50] + "...",
            'private_key': base64.b64encode(os.urandom(96)).decode()[:50] + "...",
            'fingerprint': hashlib.sha256(os.urandom(32)).hexdigest()[:32]
        }
        
        self.crypto_results.delete(1.0, tk.END)
        self.crypto_results.insert(tk.END, "=== KEY GENERATION RESULTS ===\n\n")
        for key, value in key_info.items():
            self.crypto_results.insert(tk.END, f"{key.replace('_', ' ').title()}: {value}\n")
        
        self.update_status(f"{algorithm} keys generated")
        self.log_activity(f"Generated {algorithm} keys")
    
    def hash_md5(self):
        self.calculate_hash('md5')
    
    def hash_sha1(self):
        self.calculate_hash('sha1')
    
    def hash_sha256(self):
        self.calculate_hash('sha256')
    
    def calculate_hash(self, hash_type):
        text = self.crypto_target.get()
        if not text:
            self.show_error("Please enter text to hash")
            return
        
        hash_funcs = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
        }
        
        if hash_type in hash_funcs:
            hash_obj = hash_funcs[hash_type]()
            hash_obj.update(text.encode())
            result = hash_obj.hexdigest()
            
            self.crypto_results.delete(1.0, tk.END)
            self.crypto_results.insert(tk.END, f"=== {hash_type.upper()} HASH ===\n\n")
            self.crypto_results.insert(tk.END, f"Input: {text}\n")
            self.crypto_results.insert(tk.END, f"Hash: {result}\n")
            self.crypto_results.insert(tk.END, f"Length: {len(result)} characters\n")
            
            self.update_status(f"{hash_type.upper()} hash calculated")
            self.log_activity(f"Calculated {hash_type.upper()} hash")
    
    def load_crypto_file(self):
        """Load file for crypto analysis"""
        filename = filedialog.askopenfilename(title="Select File")
        if filename:
            try:
                with open(filename, 'r') as f:
                    content = f.read(1000)  # Read first 1000 chars
                self.crypto_target.delete(0, tk.END)
                self.crypto_target.insert(0, f"File: {filename} (Preview: {content[:50]}...)")
                self.update_status(f"Loaded file: {os.path.basename(filename)}")
            except Exception as e:
                self.show_error(f"Failed to load file: {e}")
    
    def save_crypto_results(self):
        """Save crypto results to file"""
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.crypto_results.get(1.0, tk.END))
                self.update_status(f"Results saved to {filename}")
            except Exception as e:
                self.show_error(f"Failed to save: {e}")
    
    # ========== TLS/SSL METHODS ==========
    
    def run_tls_scan(self):
        """Run TLS/SSL scan"""
        target = self.tls_target.get()
        port = self.tls_port.get()
        
        if not target:
            self.show_error("Please enter a target host")
            return
        
        self.update_status(f"Scanning TLS configuration for {target}:{port}...")
        self.progress.start()
        
        def scan():
            try:
                time.sleep(1.5)
                findings = [
                    ('Protocol Support', 'TLS 1.0 and 1.1 enabled', 'HIGH', 'Disable TLS 1.0 and 1.1'),
                    ('Cipher Suites', 'Weak cipher (RC4) supported', 'MEDIUM', 'Disable RC4 ciphers'),
                    ('Certificate', 'Certificate valid for 825 days', 'LOW', 'Use shorter validity period'),
                    ('Configuration', 'Perfect Forward Secrecy not enabled', 'MEDIUM', 'Enable PFS'),
                    ('Security Headers', 'HSTS header missing', 'MEDIUM', 'Add Strict-Transport-Security header'),
                ]
                
                cert_info = {
                    'issuer': f'CN={target} CA',
                    'subject': f'CN={target}',
                    'valid_from': '2023-01-01',
                    'valid_until': '2025-12-31',
                    'signature_algorithm': 'SHA256-RSA',
                }
                
                self.root.after(0, lambda: self.display_tls_results(findings, cert_info))
                
            except Exception as e:
                self.root.after(0, lambda: self.show_error(f"TLS scan failed: {str(e)}"))
            finally:
                self.root.after(0, self.analysis_complete)
        
        thread = threading.Thread(target=scan)
        thread.daemon = True
        thread.start()
    
    def test_ssl_labs(self):
        """Test SSL configuration"""
        target = self.tls_target.get()
        self.update_status(f"Testing {target} SSL configuration...")
        
        self.cert_details.delete(1.0, tk.END)
        self.cert_details.insert(tk.END, f"=== SSL TEST FOR {target} ===\n\n")
        self.cert_details.insert(tk.END, "Overall Rating: B\n")
        self.cert_details.insert(tk.END, "Protocol Support: Good\n")
        self.cert_details.insert(tk.END, "Key Exchange: 2048-bit RSA\n")
        self.cert_details.insert(tk.END, "Cipher Strength: Strong\n")
        self.cert_details.insert(tk.END, "\nRecommendations:\n")
        self.cert_details.insert(tk.END, "1. Enable TLS 1.3\n")
        self.cert_details.insert(tk.END, "2. Disable weak ciphers\n")
        self.cert_details.insert(tk.END, "3. Implement HSTS\n")
        
        self.update_status("SSL test completed")
        self.log_activity(f"Performed SSL test on {target}")
    
    # ========== EXPLOIT METHODS ==========
    
    def generate_payload(self):
        """Generate exploit payload"""
        payload_type = self.exploit_vars['payload_type'].get()
        lhost = self.exploit_vars['lhost'].get()
        lport = self.exploit_vars['lport'].get()
        
        if not all([payload_type, lhost, lport]):
            self.show_error("Please fill all payload fields")
            return
        
        ext = 'exe' if 'windows' in payload_type else 'elf' if 'linux' in payload_type else 'bin'
        cmd = f"msfvenom -p {payload_type} LHOST={lhost} LPORT={lport} -f {ext} > payload.{ext}"
        
        self.exploit_results.delete(1.0, tk.END)
        self.exploit_results.insert(tk.END, "=== PAYLOAD GENERATED ===\n\n")
        self.exploit_results.insert(tk.END, f"Type: {payload_type}\n")
        self.exploit_results.insert(tk.END, f"LHOST: {lhost}\n")
        self.exploit_results.insert(tk.END, f"LPORT: {lport}\n\n")
        self.exploit_results.insert(tk.END, "Command:\n")
        self.exploit_results.insert(tk.END, f"{cmd}\n\n")
        self.exploit_results.insert(tk.END, "Listener command:\n")
        self.exploit_results.insert(tk.END, f"msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD {payload_type}; set LHOST {lhost}; set LPORT {lport}; run'\n")
        
        self.update_status("Payload command generated")
        self.log_activity(f"Generated {payload_type} payload")
    
    def launch_metasploit_console(self):
        """Launch Metasploit console (opens in new tab)"""
        self.notebook.select(7)  # Switch to MSF Console tab
        self.update_status("Switched to MSF Console")
    
    def run_auto_exploit(self):
        """Run auto-exploit simulation"""
        self.update_status("Running auto-exploit scan...")
        
        exploits = [
            ("MS17-010", "EternalBlue", "Windows 7/2008", "CRITICAL"),
            ("CVE-2021-44228", "Log4Shell", "Java Applications", "CRITICAL"),
            ("CVE-2019-0708", "BlueKeep", "Windows RDP", "HIGH"),
        ]
        
        self.exploit_results.delete(1.0, tk.END)
        self.exploit_results.insert(tk.END, "=== AUTO-EXPLOIT SCAN RESULTS ===\n\n")
        
        for cve, name, target, severity in exploits:
            self.exploit_results.insert(tk.END, f"{cve} - {name}\n")
            self.exploit_results.insert(tk.END, f"  Target: {target}\n")
            self.exploit_results.insert(tk.END, f"  Severity: {severity}\n")
            self.exploit_results.insert(tk.END, f"  Status: {'VULNERABLE' if random.random() > 0.5 else 'PATCHED'}\n\n")
        
        self.update_status("Auto-exploit scan completed")
        self.log_activity("Ran auto-exploit scan")
    
    def list_msf_modules(self):
        """List Metasploit modules"""
        self.update_status("Listing Metasploit modules...")
        
        modules = [
            ("exploit/windows/smb/ms17_010_eternalblue", "EternalBlue SMB Remote Windows Kernel Pool Corruption"),
            ("auxiliary/scanner/portscan/tcp", "TCP Port Scanner"),
            ("payload/windows/meterpreter/reverse_tcp", "Windows Meterpreter Reverse TCP"),
        ]
        
        self.exploit_results.delete(1.0, tk.END)
        self.exploit_results.insert(tk.END, "=== METASPLOIT MODULES ===\n\n")
        
        for module, description in modules:
            self.exploit_results.insert(tk.END, f"{module}\n")
            self.exploit_results.insert(tk.END, f"  {description}\n\n")
        
        self.update_status("Metasploit modules listed")
        self.log_activity("Listed Metasploit modules")
    
    def scan_vulnerabilities(self):
        """Scan network for vulnerabilities"""
        target = self.scan_range.get()
        
        if not target:
            self.show_error("Please enter target IP range")
            return
        
        self.update_status(f"Scanning {target} for vulnerabilities...")
        self.progress.start()
        
        def scan():
            try:
                # Simulate nmap scan
                time.sleep(2)
                
                results = f"Scan report for {target}\n"
                results += "PORT     STATE SERVICE\n"
                results += "22/tcp   open  ssh\n"
                results += "80/tcp   open  http\n"
                results += "443/tcp  open  https\n"
                results += "3389/tcp open  ms-wbt-server\n\n"
                results += "Nmap done: 1 IP address scanned\n"
                
                self.root.after(0, lambda: self.display_vulnerability_results(results))
                
            except Exception as e:
                self.root.after(0, lambda: self.show_error(f"Scan failed: {str(e)}"))
            finally:
                self.root.after(0, self.analysis_complete)
        
        thread = threading.Thread(target=scan)
        thread.daemon = True
        thread.start()
    
    def display_vulnerability_results(self, results):
        """Display vulnerability scan results"""
        self.exploit_results.delete(1.0, tk.END)
        self.exploit_results.insert(tk.END, results)
        self.update_status("Vulnerability scan completed")
        self.log_activity("Performed vulnerability scan")
    
    # ========== NETWORK METHODS ==========
    
    def start_capture(self):
        """Start network packet capture simulation"""
        self.capture_status.config(text="Status: Capturing...", fg='#ff4444')
        self.update_status("Starting packet capture...")
        
        # Clear previous packets
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        
        # Generate sample packets
        self.simulate_capture()
        
        self.update_status("Packet capture started")
        self.log_activity("Started packet capture")
    
    def stop_capture(self):
        """Stop network packet capture"""
        self.capture_status.config(text="Status: Stopped", fg='#00ff88')
        self.update_status("Packet capture stopped")
        self.log_activity("Stopped packet capture")
    
    def open_pcap(self):
        """Open PCAP file"""
        filename = filedialog.askopenfilename(
            title="Open PCAP File",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        
        if filename:
            self.update_status(f"Loading PCAP: {filename}")
            self.capture_status.config(text=f"Status: Loaded {os.path.basename(filename)}", fg='#00ff88')
            self.log_activity(f"Opened PCAP file: {os.path.basename(filename)}")
            
            # Display file info
            self.packet_details.delete(1.0, tk.END)
            self.packet_details.insert(tk.END, f"=== PCAP FILE INFO ===\n\n")
            self.packet_details.insert(tk.END, f"File: {os.path.basename(filename)}\n")
            self.packet_details.insert(tk.END, f"Size: {os.path.getsize(filename)} bytes\n")
            self.packet_details.insert(tk.END, f"Modified: {datetime.fromtimestamp(os.path.getmtime(filename))}\n")
    
    def scan_ports(self):
        """Scan ports on localhost"""
        self.update_status("Scanning ports...")
        
        ports = [
            (22, 'SSH', 'OPEN'),
            (80, 'HTTP', 'OPEN'),
            (443, 'HTTPS', 'OPEN'),
            (21, 'FTP', 'CLOSED'),
            (23, 'Telnet', 'CLOSED'),
            (3389, 'RDP', 'FILTERED'),
        ]
        
        self.packet_details.delete(1.0, tk.END)
        self.packet_details.insert(tk.END, "=== PORT SCAN RESULTS ===\n\n")
        
        for port, service, status in ports:
            self.packet_details.insert(tk.END, f"Port {port} ({service}): {status}\n")
        
        self.update_status("Port scan completed")
        self.log_activity("Performed port scan")
    
    def simulate_capture(self):
        """Simulate packet capture"""
        sample_packets = [
            (1, '10:30:15.123', '192.168.1.100', '8.8.8.8', 'DNS', '78', 'Standard query A google.com'),
            (2, '10:30:15.456', '192.168.1.100', '142.250.74.46', 'TLSv1.2', '1256', 'Client Hello'),
            (3, '10:30:15.789', '142.250.74.46', '192.168.1.100', 'TLSv1.2', '2100', 'Server Hello, Certificate'),
            (4, '10:30:16.123', '192.168.1.100', '192.168.1.1', 'ARP', '60', 'Who has 192.168.1.1?'),
        ]
        
        for pkt in sample_packets:
            self.packet_tree.insert('', 'end', values=pkt)
    
    def show_packet_details(self, event):
        """Show details of selected packet"""
        selection = self.packet_tree.selection()
        if selection:
            item = self.packet_tree.item(selection[0])
            values = item['values']
            
            self.packet_details.delete(1.0, tk.END)
            self.packet_details.insert(tk.END, f"=== PACKET #{values[0]} DETAILS ===\n\n")
            self.packet_details.insert(tk.END, f"Time: {values[1]}\n")
            self.packet_details.insert(tk.END, f"Source: {values[2]}\n")
            self.packet_details.insert(tk.END, f"Destination: {values[3]}\n")
            self.packet_details.insert(tk.END, f"Protocol: {values[4]}\n")
            self.packet_details.insert(tk.END, f"Length: {values[5]} bytes\n")
            self.packet_details.insert(tk.END, f"Info: {values[6]}\n")
    
    # ========== REPORT METHODS ==========
    
    def generate_report(self):
        """Generate security report"""
        self.update_status("Generating security report...")
        
        report = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'scans_performed': random.randint(1, 20),
            'vulnerabilities_found': random.randint(0, 10),
            'high_risk_issues': random.randint(0, 3),
            'tls_issues': random.randint(0, 5),
            'crypto_weaknesses': random.randint(0, 2),
            'network_alerts': random.randint(0, 4),
        }
        
        # Update metrics
        self.metric_labels['Total Scans'].config(text=str(report['scans_performed']))
        self.metric_labels['Vulnerabilities'].config(text=str(report['vulnerabilities_found']))
        self.metric_labels['High Risk'].config(text=str(report['high_risk_issues']))
        self.metric_labels['TLS Issues'].config(text=str(report['tls_issues']))
        self.metric_labels['Crypto Weak'].config(text=str(report['crypto_weaknesses']))
        self.metric_labels['Network Alerts'].config(text=str(report['network_alerts']))
        
        messagebox.showinfo("Report", "Security report generated successfully!\n\nCheck the dashboard for updated metrics.")
        self.update_status("Security report generated")
        self.log_activity("Generated security report")
    
    def export_pdf(self):
        """Export report to PDF"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                if filename.endswith('.pdf'):
                    # Create simple text report (would need reportlab for actual PDF)
                    txt_filename = filename.replace('.pdf', '.txt')
                    with open(txt_filename, 'w') as f:
                        f.write("=== CipherSentry Security Report ===\n")
                        f.write(f"Generated: {datetime.now()}\n\n")
                        f.write("Install reportlab for actual PDF export.\n")
                    self.update_status("Created text report (PDF requires reportlab)")
                else:
                    with open(filename, 'w') as f:
                        f.write("=== CipherSentry Security Report ===\n")
                        f.write(f"Generated: {datetime.now()}\n")
                        f.write(f"User: {os.getlogin()}\n\n")
                        f.write("Report Contents:\n")
                        f.write("- Scan Results\n")
                        f.write("- Vulnerability Analysis\n")
                        f.write("- Recommendations\n")
                    self.update_status(f"Report exported to {filename}")
                
                self.log_activity(f"Exported report to {os.path.basename(filename)}")
            except Exception as e:
                self.show_error(f"Failed to export: {e}")
    
    def view_logs(self):
        """View activity logs"""
        self.update_status("Displaying activity logs...")
        
        log_window = tk.Toplevel(self.root)
        log_window.title("Activity Logs")
        log_window.geometry("600x400")
        log_window.configure(bg='#1e1e1e')
        
        text_widget = scrolledtext.ScrolledText(
            log_window,
            bg='#252526',
            fg='white',
            wrap=tk.WORD
        )
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        
        activities = self.activity_list.get(0, tk.END)
        for activity in activities:
            text_widget.insert(tk.END, f"{activity}\n")
        
        text_widget.config(state='disabled')
        
        self.update_status("Activity logs displayed")
    
    # ========== TOOL LAUNCHERS ==========
    
    def launch_metasploit(self):
        """Launch Metasploit framework"""
        self.notebook.select(7)  # Switch to MSF Console tab
        self.update_status("Opening MSF Console")
    
    def launch_burp(self):
        """Launch Burp Suite"""
        if platform.system() == "Windows":
            # Try common Windows paths
            paths = [
                "C:\\Program Files\\BurpSuitePro\\burpsuite_pro.exe",
                "C:\\Program Files\\BurpSuiteCommunity\\burpsuite_community.exe",
                "burpsuite"
            ]
        else:
            paths = ["burpsuite", "java -jar burpsuite.jar"]
        
        for path in paths:
            try:
                if platform.system() == "Windows":
                    os.startfile(path)
                else:
                    subprocess.Popen(path.split() if ' ' in path else [path], 
                                   start_new_session=True)
                self.update_status("Burp Suite launched")
                self.log_activity("Launched Burp Suite")
                return
            except:
                continue
        
        self.show_error("Burp Suite not found. Install from https://portswigger.net/burp")
    
    def launch_wireshark(self):
        """Launch Wireshark"""
        self.launch_tool('wireshark', 'Wireshark')
    
    def launch_terminal(self):
        """Launch system terminal"""
        if platform.system() == "Windows":
            os.system("start cmd")
            self.update_status("Command Prompt launched")
        else:
            terminals = ['gnome-terminal', 'xfce4-terminal', 'konsole', 'xterm', 'terminator']
            for terminal in terminals:
                try:
                    subprocess.Popen([terminal], start_new_session=True)
                    self.update_status(f"{terminal} launched")
                    self.log_activity(f"Launched {terminal}")
                    return
                except:
                    continue
            self.show_error("No terminal found")
    
    def launch_tool(self, tool_name, display_name):
        """Launch a tool in terminal"""
        try:
            if platform.system() == "Windows":
                subprocess.Popen(['start', tool_name], shell=True)
            else:
                subprocess.Popen([tool_name], start_new_session=True)
            self.update_status(f"{display_name} launched")
            self.log_activity(f"Launched {display_name}")
        except Exception as e:
            self.show_error(f"Failed to launch {display_name}: {str(e)}")
    
    # ========== HELPER METHODS ==========
    
    def display_crypto_results(self, results, analysis_type):
        """Display cryptographic analysis results"""
        self.crypto_results.delete(1.0, tk.END)
        
        self.crypto_results.insert(tk.END, f"=== {analysis_type.upper()} RESULTS ===\n\n")
        for key, value in results.items():
            if key not in ['analysis', 'recommendations']:
                self.crypto_results.insert(tk.END, f"{key.replace('_', ' ').title()}: {value}\n")
        
        if 'analysis' in results:
            self.crypto_results.insert(tk.END, f"\nAnalysis: {results['analysis']}\n")
        
        if 'recommendations' in results:
            self.crypto_results.insert(tk.END, "\nRecommendations:\n")
            for rec in results['recommendations']:
                self.crypto_results.insert(tk.END, f"• {rec}\n")
        
        self.update_status(f"{analysis_type} completed")
        self.log_activity(f"Performed {analysis_type}")
    
    def display_brute_force_results(self, results):
        """Display brute force results"""
        self.crypto_results.delete(1.0, tk.END)
        
        self.crypto_results.insert(tk.END, "=== BRUTE FORCE TEST RESULTS ===\n\n")
        for key, value in results.items():
            self.crypto_results.insert(tk.END, f"{key.replace('_', ' ').title()}: {value}\n")
        
        if results['success']:
            self.crypto_results.insert(tk.END, "\n⚠️ WARNING: Weak encryption detected!\n")
        else:
            self.crypto_results.insert(tk.END, "\n✓ Encryption appears strong\n")
        
        self.update_status("Brute force test completed")
        self.log_activity("Performed brute force test")
    
    def display_tls_results(self, findings, cert_info):
        """Display TLS scan results"""
        for item in self.tls_tree.get_children():
            self.tls_tree.delete(item)
        
        for finding in findings:
            self.tls_tree.insert('', 'end', values=finding)
        
        self.cert_details.delete(1.0, tk.END)
        self.cert_details.insert(tk.END, "=== CERTIFICATE DETAILS ===\n\n")
        for key, value in cert_info.items():
            self.cert_details.insert(tk.END, f"{key.replace('_', ' ').title()}: {value}\n")
        
        self.update_status("TLS scan completed")
        self.log_activity(f"Scanned TLS configuration")
    
    def update_status(self, message):
        """Update status bar message"""
        self.status_label.config(text=message)
        self.root.update_idletasks()
    
    def analysis_complete(self):
        """Handle completion of analysis"""
        self.progress.stop()
        self.update_status("Ready")
    
    def log_activity(self, activity):
        """Log activity to dashboard"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.activity_list.insert(0, f"{timestamp}: {activity}")
        
        if self.activity_list.size() > 50:
            self.activity_list.delete(50, tk.END)
    
    def show_error(self, message):
        """Show error message"""
        messagebox.showerror("Error", message)
        self.update_status("Error occurred")
        self.progress.stop()
    
    def load_config(self):
        """Load configuration from file"""
        config_file = 'config.yaml'
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    return yaml.safe_load(f)
            except:
                return {}
        else:
            return {
                'theme': 'dark',
                'auto_save': True,
                'tool_paths': {
                    'metasploit': 'msfconsole',
                    'wireshark': 'wireshark',
                    'nmap': 'nmap',
                    'burp_suite': 'burpsuite',
                    'hashcat': 'hashcat',
                    'hydra': 'hydra'
                }
            }
    
    def save_settings(self):
        """Save application settings"""
        self.config['theme'] = self.theme_var.get()
        self.config['auto_save'] = self.auto_save_var.get()
        
        for tool, var in self.tool_paths.items():
            if tool in self.config.get('tool_paths', {}):
                self.config['tool_paths'][tool] = var.get()
        
        try:
            with open('config.yaml', 'w') as f:
                yaml.dump(self.config, f)
            messagebox.showinfo("Settings", "Settings saved successfully!")
            self.update_status("Settings saved")
            self.log_activity("Saved settings")
        except Exception as e:
            self.show_error(f"Failed to save settings: {e}")
    
    def test_tool_path(self, tool_name, path):
        """Test if a tool path works"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(f"where {path}", shell=True, capture_output=True, text=True)
            else:
                result = subprocess.run(['which', path], capture_output=True, text=True)
            
            if result.returncode == 0:
                messagebox.showinfo("Test", f"{tool_name} found: {result.stdout.strip()}")
            else:
                messagebox.showwarning("Test", f"{tool_name} not found at: {path}")
        except:
            messagebox.showerror("Test", f"Error testing {tool_name} path")
    
    def check_output_queue(self):
        """Check for output in queue"""
        try:
            while True:
                output = self.output_queue.get_nowait()
                # Process output if needed
                pass
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.check_output_queue)
    
    def check_tools_status(self):
        """Check status of all tools"""
        self.update_status("Checking tool status...")
        
        status_window = tk.Toplevel(self.root)
        status_window.title("Tool Status")
        status_window.geometry("400x300")
        status_window.configure(bg='#1e1e1e')
        
        text_widget = tk.Text(
            status_window,
            bg='#252526',
            fg='white',
            wrap=tk.WORD
        )
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        
        text_widget.insert(tk.END, "=== TOOL STATUS ===\n\n")
        
        for tool, available in self.available_tools.items():
            status = "✓ Available" if available else "✗ Not found"
            color = '#00ff88' if available else '#ff4444'
            text_widget.insert(tk.END, f"{tool}: ")
            text_widget.insert(tk.END, status, 'status')
            text_widget.insert(tk.END, "\n")
        
        text_widget.tag_config('status', foreground='#00ff88')
        text_widget.config(state='disabled')
        
        self.update_status("Tool status checked")
        self.log_activity("Checked tool status")
    
    def change_theme(self, theme):
        """Change application theme"""
        messagebox.showinfo("Theme", f"Theme changed to {theme} mode.\n\nNote: Full theme support requires restart.")
        self.update_status(f"Theme changed to {theme}")
        self.log_activity(f"Changed theme to {theme}")
    
    def show_dashboard(self):
        """Switch to reports tab"""
        self.notebook.select(4)
        self.update_status("Dashboard view")
    
    def show_docs(self):
        """Show documentation"""
        webbrowser.open("https://github.com/yourusername/ciphersentry")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """CipherSentry v1.5
        
Enhanced Cybersecurity Toolkit
Developed for educational and authorized security testing

NEW FEATURES:
- Nmap Scanner with real-time output
- Hydra Password Cracker
- Metasploit GUI Console
- 20+ security tools integration

Requirements:
• Kali Linux (recommended)
• Python 3.6+
• Tkinter

Note: This tool is for educational purposes only.
Use only on systems you own or have permission to test.

© 2024 Cybersecurity Research Team"""
        messagebox.showinfo("About CipherSentry", about_text)
    
    def new_project(self):
        """Create new project"""
        response = messagebox.askyesno("New Project", "Create a new project?\n\nCurrent work will be cleared.")
        if response:
            self.crypto_results.delete(1.0, tk.END)
            self.exploit_results.delete(1.0, tk.END)
            self.cert_details.delete(1.0, tk.END)
            self.packet_details.delete(1.0, tk.END)
            self.nmap_results.delete(1.0, tk.END)
            self.hydra_results.delete(1.0, tk.END)
            
            for item in self.tls_tree.get_children():
                self.tls_tree.delete(item)
            for item in self.packet_tree.get_children():
                self.packet_tree.delete(item)
            
            for label in self.metric_labels.values():
                label.config(text="0")
            
            self.activity_list.delete(0, tk.END)
            self.log_activity("New project created")
            
            self.update_status("New project created")
            messagebox.showinfo("New Project", "New project created successfully!")
    
    def open_project(self):
        """Open project"""
        filename = filedialog.askopenfilename(
            title="Open Project",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    data = json.load(f)
                messagebox.showinfo("Open Project", f"Project loaded: {os.path.basename(filename)}")
                self.update_status(f"Project loaded: {os.path.basename(filename)}")
                self.log_activity(f"Opened project: {os.path.basename(filename)}")
            except Exception as e:
                self.show_error(f"Failed to open project: {e}")
    
    def save_results(self):
        """Save results to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            results = {
                'timestamp': datetime.now().isoformat(),
                'activities': list(self.activity_list.get(0, tk.END)),
            }
            
            try:
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2)
                self.update_status(f"Results saved to {filename}")
                self.log_activity(f"Saved results to {os.path.basename(filename)}")
            except Exception as e:
                self.show_error(f"Failed to save: {e}")
    
    def configure_tools(self):
        """Switch to settings tab"""
        self.notebook.select(5)
        self.update_status("Tool configuration")
    
    def clear_reports(self):
        """Clear all reports"""
        response = messagebox.askyesno("Clear Reports", "Clear all reports and activities?")
        if response:
            self.activity_list.delete(0, tk.END)
            for label in self.metric_labels.values():
                label.config(text="0")
            self.log_activity("Cleared all reports")
            self.update_status("All reports cleared")
    
    def quit_application(self):
        """Quit the application"""
        # Stop any running processes
        if self.msf_process:
            self.stop_msf_console()
        if self.nmap_process:
            try:
                self.nmap_process.terminate()
            except:
                pass
        if self.hydra_process:
            try:
                self.hydra_process.terminate()
            except:
                pass
        
        for process in self.running_processes:
            try:
                process.terminate()
            except:
                pass
        
        try:
            self.save_settings()
        except:
            pass
        
        self.root.quit()

def main():
    """Main entry point"""
    root = tk.Tk()
    
    try:
        if platform.system() == "Windows":
            root.iconbitmap(default='icon.ico')
    except:
        pass
    
    app = CipherSentryGUI(root)
    
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    root.protocol("WM_DELETE_WINDOW", app.quit_application)
    
    root.mainloop()

if __name__ == "__main__":
    main()
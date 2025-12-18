#!/bin/bash

# Install Python dependencies
pip install cryptography pillow matplotlib

# Install common terminals (for launching tools)
sudo apt install -y gnome-terminal xterm

# Install core Kali tools
sudo apt install -y \
    metasploit-framework \
    nmap \
    wireshark \
    burpsuite \
    hashcat \
    john \
    sqlmap \
    aircrack-ng

# Fix permissions
sudo dpkg-reconfigure wireshark-common
sudo usermod -a -G wireshark $USER

echo "Installation complete! Logout and login for Wireshark permissions."
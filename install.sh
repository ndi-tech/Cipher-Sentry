#!/bin/bash
# install_ciphersentry.sh

echo "⚡ CipherSentry v3.0 Installation ⚡"
echo "===================================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo "⚠️  Warning: Running as root is not recommended for GUI applications"
    read -p "Continue anyway? [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Update system
echo "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install --upgrade pip
pip3 install psutil pyperclip pillow

# Install required terminals
echo "Installing terminal emulators..."
sudo apt install -y gnome-terminal xterm terminator

# Install ALL Kali Linux tools
echo "Installing Kali Linux tools..."
echo "This may take a while..."

# Essential tools
sudo apt install -y \
    metasploit-framework \
    nmap \
    wireshark \
    burpsuite \
    sqlmap \
    hashcat \
    john \
    hydra \
    aircrack-ng \
    recon-ng \
    theharvester \
    nikto \
    dirb \
    gobuster \
    wpscan \
    ettercap-graphical \
    bettercap \
    wifite \
    kismet \
    binwalk \
    foremost \
    volatility \
    zenmap \
    crunch \
    cewl \
    wordlists \
    seclists

# Fix Wireshark permissions
echo "Configuring Wireshark permissions..."
sudo dpkg-reconfigure wireshark-common
sudo usermod -a -G wireshark $USER

# Create desktop shortcut
echo "Creating desktop shortcut..."
cat > ~/Desktop/CipherSentry.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=CipherSentry
Comment=Ultimate Cybersecurity Toolkit
Exec=python3 $PWD/main.py
Icon=$PWD/icon.png
Terminal=false
Categories=Security;Utility;
EOF

chmod +x ~/Desktop/CipherSentry.desktop

# Download icon if not exists
if [ ! -f "icon.png" ]; then
    echo "Downloading icon..."
    wget -q https://img.icons8.com/color/96/000000/cyber-security.png -O icon.png
fi

# Create requirements file
echo "Creating requirements.txt..."
cat > requirements.txt << EOF
psutil>=5.8.0
pyperclip>=1.8.2
Pillow>=8.3.0
EOF

echo ""
echo "✅ Installation complete!"
echo ""
echo "To run CipherSentry:"
echo "1. cd $(pwd)"
echo "2. python3 main.py"
echo ""
echo "For best experience:"
echo "- Logout and login again for Wireshark permissions"
echo "- Run Burp Suite once to accept license"
echo "- Configure Metasploit database: sudo msfdb init"
echo ""
echo "Enjoy CipherSentry v3.0! ⚡"
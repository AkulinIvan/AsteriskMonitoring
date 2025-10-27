#!/bin/bash

# 🎯 Premium Asterisk Monitor Installer
set -e

echo "🚀 Installing Asterisk Monitor Premium Edition..."

# System validation
validate_system() {
    echo "🔍 Validating system requirements..."
    
    # Check dependencies
    local deps=("go" "asterisk" "git")
    for dep in "${deps[@]}"; do
        if ! command -v $dep &> /dev/null; then
            echo "❌ Missing dependency: $dep"
            return 1
        fi
    done
    
    # Check system resources
    local mem=$(free -g | awk 'NR==2{print $2}')
    if [ $mem -lt 2 ]; then
        echo "⚠️  Warning: Recommended 2GB+ RAM for premium features"
    fi
    
    echo "✅ System validation passed"
}

# Premium installation
install_premium() {
    echo "💎 Installing premium features..."
    
    # Create enterprise directory structure
    local dirs=(
        "/opt/asterisk-monitor"
        "/etc/asterisk-monitor" 
        "/var/log/asterisk-monitor"
        "/var/lib/asterisk-monitor"
        "/usr/share/asterisk-monitor/web"
    )
    
    for dir in "${dirs[@]}"; do
        sudo mkdir -p "$dir"
        sudo chmod 755 "$dir"
    done
    
    # Initialize Go module with premium dependencies
    if [ ! -f "go.mod" ]; then
        go mod init asterisk-monitor-premium
        cat >> go.mod << 'EOF'
module asterisk-monitor-premium

go 1.19

require (
    github.com/prometheus/client_golang v1.14.0
    github.com/gorilla/mux v1.8.0
    github.com/sirupsen/logrus v1.9.0
    github.com/patrickmn/go-cache v2.1.0+incompatible
)
EOF
    fi
    
    # Download premium dependencies
    echo "📦 Downloading enterprise dependencies..."
    go mod tidy
    
    # Build with optimizations
    echo "⚡ Building with performance optimizations..."
    go build -ldflags="-s -w -X main.Version=2.0.0" -o asterisk-monitor main.go
    
    # Install service with security hardening
    install_enterprise_service
}

install_enterprise_service() {
    echo "🛡️ Installing enterprise service..."
    
    sudo tee /etc/systemd/system/asterisk-monitor.service > /dev/null <<EOF
[Unit]
Description=Asterisk Monitor Premium Edition
Documentation=https://github.com/company/asterisk-monitor
After=network.target asterisk.service
Wants=asterisk.service
Requires=asterisk.service

[Service]
Type=exec
User=asterisk
Group=asterisk
WorkingDirectory=/opt/asterisk-monitor
ExecStart=/opt/asterisk-monitor/asterisk-monitor
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/asterisk-monitor /var/lib/asterisk-monitor
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

# Resource management
LimitNOFILE=65536
LimitNPROC=4096
MemoryMax=512M
CPUQuota=80%

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=asterisk-monitor

[Install]
WantedBy=multi-user.target
EOF

    # Install application
    sudo cp asterisk-monitor /opt/asterisk-monitor/
    sudo cp -r web/* /usr/share/asterisk-monitor/web/
    
    # Set permissions
    sudo chown -R asterisk:asterisk /opt/asterisk-monitor /var/log/asterisk-monitor /var/lib/asterisk-monitor
    sudo chmod 750 /opt/asterisk-monitor /var/log/asterisk-monitor /var/lib/asterisk-monitor
    
    # Enable and start
    sudo systemctl daemon-reload
    sudo systemctl enable asterisk-monitor
    sudo systemctl start asterisk-monitor
}

# Post-installation setup
post_install() {
    echo "🎉 Installation completed!"
    
    # Show access information
    local ip=$(hostname -I | awk '{print $1}')
    echo ""
    echo "╔══════════════════════════════════════════════════╗"
    echo "║              🎯 ACCESS INFORMATION              ║"
    echo "╠══════════════════════════════════════════════════╣"
    echo "║ Web Dashboard: http://$ip:2112                 ║"
    echo "║ Metrics:       http://$ip:2112/metrics        ║"
    echo "║ API:           http://$ip:2112/api/health     ║"
    echo "║ Logs:          /var/log/asterisk-monitor/      ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo ""
    echo "🔧 Quick Commands:"
    echo "   sudo systemctl status asterisk-monitor"
    echo "   sudo journalctl -u asterisk-monitor -f"
    echo "   curl http://localhost:2112/api/health"
    echo ""
}

# Main installation flow
main() {
    echo "💎 Asterisk Monitor v2.0.0"
    echo "==========================================="
    
    validate_system
    install_premium
    
    # Wait for service to start
    sleep 3
    
    # Verify installation
    if sudo systemctl is-active --quiet asterisk-monitor; then
        post_install
    else
        echo "❌ Service failed to start"
        sudo systemctl status asterisk-monitor --no-pager
        exit 1
    fi
}

main "$@"
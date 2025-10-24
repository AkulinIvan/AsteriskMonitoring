#!/bin/bash

# Компилируем программу
go build -o asterisk-monitor

# Создаем systemd сервис
sudo tee /etc/systemd/system/asterisk-monitor.service > /dev/null <<EOF
[Unit]
Description=Asterisk Problem Calls Monitor
After=network.target asterisk.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/asterisk-monitor
ExecStart=/opt/asterisk-monitor/asterisk-monitor
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Создаем директорию и копируем бинарник
sudo mkdir -p /opt/asterisk-monitor
sudo cp asterisk-monitor /opt/asterisk-monitor/
sudo mkdir -p /var/log/asterisk-monitor

# Даем права
sudo chmod +x /opt/asterisk-monitor/asterisk-monitor

# Перезагружаем systemd и запускаем сервис
sudo systemctl daemon-reload
sudo systemctl enable asterisk-monitor
sudo systemctl start asterisk-monitor

echo "Сервис установлен и запущен"
echo "Просмотр логов: sudo tail -f /var/log/asterisk-monitor/calls_problem_online.log"
echo "Статус сервиса: sudo systemctl status asterisk-monitor"
#!/bin/bash

set -e  # Выход при ошибке

echo "Установка Asterisk Monitor Service..."

# Проверяем наличие Go
if ! command -v go &> /dev/null; then
    echo "Ошибка: Go не установлен. Установите Go сначала."
    exit 1
fi

# Проверяем наличие Asterisk
if ! command -v asterisk &> /dev/null; then
    echo "Ошибка: Asterisk не установлен или не найден в PATH."
    exit 1
fi

# Инициализируем Go модуль если нужно
if [ ! -f "go.mod" ]; then
    echo "Инициализация Go модуля..."
    go mod init asterisk-monitor
fi

# Скачиваем зависимости
echo "Скачивание зависимостей..."
go mod tidy

# Компилируем программу
echo "Компиляция программы..."
go build -o asterisk-monitor main.go

if [ ! -f "asterisk-monitor" ]; then
    echo "Ошибка: Не удалось скомпилировать программу"
    exit 1
fi

# Создаем systemd сервис
echo "Создание systemd сервиса..."
sudo tee /etc/systemd/system/asterisk-monitor.service > /dev/null <<EOF
[Unit]
Description=Asterisk Problem Calls Monitor
After=network.target asterisk.service
Wants=asterisk.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/asterisk-monitor
ExecStart=/opt/asterisk-monitor/asterisk-monitor
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Создаем директорию и копируем файлы
echo "Копирование файлов..."
sudo mkdir -p /opt/asterisk-monitor
sudo mkdir -p /etc/asterisk-monitor
sudo mkdir -p /var/log/asterisk-monitor

# Копируем бинарник
sudo cp asterisk-monitor /opt/asterisk-monitor/

# Создаем конфигурационный файл
sudo tee /etc/asterisk-monitor/config.conf > /dev/null <<EOF
# Конфигурация мониторинга Asterisk
max_ring_duration=30
max_call_duration=3600
bubbling_threshold=3
packet_loss_threshold=5.0
jitter_threshold=50.0
short_call_threshold=3
EOF

# Даем права
sudo chmod +x /opt/asterisk-monitor/asterisk-monitor
sudo chmod 644 /etc/asterisk-monitor/config.conf

# Создаем директорию для CDR если не существует
sudo mkdir -p /var/log/asterisk/cdr-csv

# Даем права на логи
sudo chown -R root:root /var/log/asterisk-monitor
sudo chmod 755 /var/log/asterisk-monitor

# Перезагружаем systemd и запускаем сервис
echo "Запуск сервиса..."
sudo systemctl daemon-reload
sudo systemctl enable asterisk-monitor
sudo systemctl start asterisk-monitor

# Проверяем статус
echo "Проверка статуса сервиса..."
sleep 2
sudo systemctl status asterisk-monitor --no-pager

echo ""
echo "✅ Сервис успешно установлен и запущен"
echo "📊 Просмотр логов: sudo tail -f /var/log/asterisk-monitor/calls_problem_online.log"
echo "🔍 Статус сервиса: sudo systemctl status asterisk-monitor"
echo "🔄 Перезапуск сервиса: sudo systemctl restart asterisk-monitor"
echo "❌ Остановка сервиса: sudo systemctl stop asterisk-monitor"
echo "📝 Логи через journalctl: sudo journalctl -u asterisk-monitor -f"
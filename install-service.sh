#!/bin/bash

set -e

echo "🚀 Установка Asterisk Monitor Service..."

# Проверяем наличие Go
if ! command -v go &> /dev/null; then
    echo "❌ Ошибка: Go не установлен. Установите Go сначала."
    exit 1
fi

# Проверяем наличие Asterisk
if ! command -v asterisk &> /dev/null; then
    echo "❌ Ошибка: Asterisk не установлен или не найден в PATH."
    exit 1
fi

# Создаем необходимые директории
echo "📁 Создание директорий..."
sudo mkdir -p /opt/asterisk-monitor
sudo mkdir -p /etc/asterisk-monitor
sudo mkdir -p /var/log/asterisk-monitor
sudo mkdir -p /var/log/asterisk/cdr-csv

# Инициализируем Go модуль если нужно
if [ ! -f "go.mod" ]; then
    echo "🔧 Инициализация Go модуля..."
    go mod init asterisk-monitor
fi

# Скачиваем зависимости
echo "📦 Скачивание зависимостей..."
go mod tidy

# Компилируем программу
echo "⚙️ Компиляция программы..."
if ! go build -o asterisk-monitor main.go; then
    echo "❌ Ошибка компиляции программы"
    exit 1
fi

if [ ! -f "asterisk-monitor" ]; then
    echo "❌ Ошибка: Не удалось скомпилировать программу"
    exit 1
fi

# Создаем systemd сервис
echo "🔧 Создание systemd сервиса..."
sudo tee /etc/systemd/system/asterisk-monitor.service > /dev/null <<EOF
[Unit]
Description=Asterisk Problem Calls Monitor
After=network.target asterisk.service
Wants=asterisk.service
Requires=asterisk.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/asterisk-monitor
ExecStart=/opt/asterisk-monitor/asterisk-monitor
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Ограничения для безопасности
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/asterisk-monitor /var/log/asterisk/cdr-csv

[Install]
WantedBy=multi-user.target
EOF

# Копируем бинарник
echo "📄 Копирование файлов..."
sudo cp asterisk-monitor /opt/asterisk-monitor/

# Создаем конфигурационный файл
echo "⚙️ Создание конфигурации..."
sudo tee /etc/asterisk-monitor/config.conf > /dev/null <<EOF
# Конфигурация мониторинга Asterisk

# Временные параметры (в секундах)
max_ring_duration=30
max_call_duration=3600
short_call_threshold=3
check_interval=30

# Пороги для детектирования проблем
bubbling_threshold=3
packet_loss_threshold=5.0
jitter_threshold=50.0

# Настройки логов (в МБ)
log_max_size=100
log_max_backups=3
EOF

# Настраиваем права
echo "🔒 Настройка прав доступа..."
sudo chmod +x /opt/asterisk-monitor/asterisk-monitor
sudo chmod 644 /etc/asterisk-monitor/config.conf
sudo chown -R root:root /var/log/asterisk-monitor
sudo chmod 755 /var/log/asterisk-monitor

# Перезагружаем systemd и запускаем сервис
echo "🔌 Запуск сервиса..."
sudo systemctl daemon-reload
sudo systemctl enable asterisk-monitor
sudo systemctl start asterisk-monitor

# Проверяем статус
echo "🔍 Проверка статуса сервиса..."
sleep 3
if ! sudo systemctl status asterisk-monitor --no-pager; then
    echo "❌ Ошибка запуска сервиса"
    exit 1
fi

echo ""
echo "✅ Сервис успешно установлен и запущен"
echo "📊 Просмотр логов: sudo tail -f /var/log/asterisk-monitor/calls_problem_online.log"
echo "🔍 Статус сервиса: sudo systemctl status asterisk-monitor"
echo "🔄 Перезапуск сервиса: sudo systemctl restart asterisk-monitor"
echo "❌ Остановка сервиса: sudo systemctl stop asterisk-monitor"
echo "📝 Логи через journalctl: sudo journalctl -u asterisk-monitor -f"
echo "📈 Статистика: журнал в /var/log/asterisk-monitor/calls_problem_online.log"
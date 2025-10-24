Инструкция по использованию:

Дайте права на выполнение скрипту установки install-service.sh: chmod +x install-service.sh

Запустите установку: sudo ./install-service.sh

Особенности скрипта:

Мониторит проблемные вызовы каждые 10 секунд

Обнаруживает различные типы проблем: "булькание", занятые линии, неудачные вызовы

Создает необходимые директории автоматически

Логирует проблемы в указанный файл

Может работать как systemd сервис

Включает детектор долгих вызовов (>1 часа)

Просмотр логов:
bash
tail -f /var/log/asterisk-monitor/calls_problem_online.log

Управление сервисом:
bash
sudo systemctl status asterisk-monitor
sudo systemctl restart asterisk-monitor
sudo systemctl stop asterisk-monitor
package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	logFile    = "/var/log/asterisk-monitor/calls_problem_online.log"
	cdrFile    = "/var/log/asterisk/cdr-csv/Master.csv"
	configFile = "/etc/asterisk-monitor/config.conf"

	// AMI конфигурация
	amiHost     = "localhost"
	amiPort     = "5038"
	amiUsername = "admin"
	amiPassword = ",fhf,firf"
)

// AMIClient для подключения к Asterisk Manager Interface
type AMIClient struct {
	conn      net.Conn
	events    chan string
	connected bool
	reconnect chan bool
	stop      chan bool
}

// ProblemCall представляет проблемный вызов
type ProblemCall struct {
	Timestamp string
	Channel   string
	CallerID  string
	Problem   string
	Details   string
	Severity  string
}

// ActiveCall отслеживает активные вызовы
type ActiveCall struct {
	Channel     string
	CallerID    string
	Destination string
	State       string
	StartTime   time.Time
	LastUpdate  time.Time
}

// QualityMetrics представляет метрики качества связи
type QualityMetrics struct {
	Channel    string
	PacketLoss float64
	Jitter     float64
	Latency    int
	MOS        float64
	RTPErrors  int
	Timestamp  time.Time
}

// CallPattern представляет шаблон вызова для детектирования булькания
type CallPattern struct {
	Channel      string
	CallerID     string
	RingCount    int
	LastState    string
	StateChanges []time.Time
	ShortCalls   int
	LastReset    time.Time
}

// Config представляет конфигурацию мониторинга
type Config struct {
	MaxRingDuration     int
	MaxCallDuration     int
	BubblingThreshold   int
	PacketLossThreshold float64
	JitterThreshold     float64
	ShortCallThreshold  int
	AMIUsername         string
	AMIPassword         string
}

var (
	activeCalls       = make(map[string]*ActiveCall)
	activeMutex       = &sync.Mutex{}
	callPatterns      = make(map[string]*CallPattern)
	patternsMutex     = &sync.Mutex{}
	config            Config
	monitoring        = false
	lastAsteriskCheck = time.Now()
	problemHistory    = make(map[string]time.Time)
	amiClient         *AMIClient
)

func main() {
	fmt.Println("Asterisk Reactive Monitor запущен...")
	fmt.Printf("Логи будут записываться в: %s\n", logFile)

	// Загружаем конфигурацию
	if err := loadConfig(); err != nil {
		log.Printf("Ошибка загрузки конфигурации: %v. Используются значения по умолчанию.", err)
		config = Config{
			MaxRingDuration:     30,
			MaxCallDuration:     3600,
			BubblingThreshold:   3,
			PacketLossThreshold: 5.0,
			JitterThreshold:     50.0,
			ShortCallThreshold:  3,
			AMIUsername:         "admin",
			AMIPassword:         "password",
		}
	}

	// Создаем директорию для логов если не существует
	if err := os.MkdirAll("/var/log/asterisk-monitor", 0755); err != nil {
		log.Fatalf("Ошибка создания директории: %v", err)
	}

	// Инициализируем AMI клиент
	amiClient = NewAMIClient()

	// Запускаем AMI клиент для прослушивания событий
	go amiClient.Start()

	// Запускаем мониторинг активных вызовов
	go monitorActiveCalls()

	// Запускаем фоновый мониторинг для редких проверок
	go backgroundMonitoring()

	fmt.Println("✅ Мониторинг запущен в реактивном режиме")
	fmt.Println("📞 Мониторинг активируется автоматически при звонках")

	// Останавливаемся только при сигнале завершения
	select {}
}

// NewAMIClient создает новый AMI клиент
func NewAMIClient() *AMIClient {
	return &AMIClient{
		events:    make(chan string, 100),
		reconnect: make(chan bool, 1),
		stop:      make(chan bool, 1),
		connected: false,
	}
}

// Start запускает AMI клиент
func (a *AMIClient) Start() {
	for {
		select {
		case <-a.stop:
			return
		default:
			if err := a.connect(); err != nil {
				log.Printf("❌ Ошибка подключения к AMI: %v. Повтор через 10 секунд...", err)
				time.Sleep(10 * time.Second)
				continue
			}

			// Успешное подключение
			a.connected = true
			log.Println("✅ Успешно подключено к AMI")

			// Запускаем чтение событий
			if err := a.readEvents(); err != nil {
				log.Printf("❌ Ошибка чтения событий AMI: %v", err)
				a.connected = false
				a.conn.Close()
				time.Sleep(5 * time.Second)
			}
		}
	}
}

// connect устанавливает соединение с AMI
func (a *AMIClient) connect() error {
	log.Println("Подключаемся к Asterisk Manager Interface...")

	conn, err := net.Dial("tcp", amiHost+":"+amiPort)
	if err != nil {
		return fmt.Errorf("ошибка подключения: %v", err)
	}

	// Устанавливаем таймауты
	conn.SetReadDeadline(time.Time{}) // Без таймаута

	// Аутентификация в AMI
	authCommand := fmt.Sprintf("Action: Login\r\nUsername: %s\r\nSecret: %s\r\nEvents: on\r\n\r\n",
		config.AMIUsername, config.AMIPassword)

	if _, err := conn.Write([]byte(authCommand)); err != nil {
		conn.Close()
		return fmt.Errorf("ошибка аутентификации: %v", err)
	}

	// Читаем ответ
	reader := bufio.NewReader(conn)
	response := ""
	for i := 0; i < 10; i++ { // Читаем несколько строк ответа
		line, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return fmt.Errorf("ошибка чтения ответа: %v", err)
		}
		response += line

		if strings.Contains(line, "Message: Authentication accepted") {
			a.conn = conn
			return nil
		}

		if strings.Contains(line, "Message: Authentication failed") {
			conn.Close()
			return fmt.Errorf("аутентификация не удалась")
		}
	}

	conn.Close()
	return fmt.Errorf("таймаут аутентификации")
}

// readEvents читает события из AMI
func (a *AMIClient) readEvents() error {
	reader := bufio.NewReader(a.conn)
	buffer := ""

	for {
		// Устанавливаем таймаут чтения
		a.conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("ошибка чтения: %v", err)
		}

		buffer += line

		// События разделяются пустой строкой
		if strings.TrimSpace(line) == "" && strings.TrimSpace(buffer) != "" {
			// Отправляем событие в канал
			select {
			case a.events <- buffer:
				// Событие отправлено
			default:
				log.Printf("⚠️  Переполнение буфера событий AMI")
			}
			buffer = ""
		}
	}
}

// processEvents обрабатывает события AMI
func (a *AMIClient) processEvents() {
	for event := range a.events {
		go handleAMIEvent(event)
	}
}

func loadConfig() error {
	// Чтение конфигурации из файла
	data, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "max_ring_duration":
			config.MaxRingDuration, _ = strconv.Atoi(value)
		case "max_call_duration":
			config.MaxCallDuration, _ = strconv.Atoi(value)
		case "bubbling_threshold":
			config.BubblingThreshold, _ = strconv.Atoi(value)
		case "packet_loss_threshold":
			config.PacketLossThreshold, _ = strconv.ParseFloat(value, 64)
		case "jitter_threshold":
			config.JitterThreshold, _ = strconv.ParseFloat(value, 64)
		case "short_call_threshold":
			config.ShortCallThreshold, _ = strconv.Atoi(value)
		case "ami_username":
			config.AMIUsername = value
		case "ami_password":
			config.AMIPassword = value
		}
	}

	return nil
}

// handleAMIEvent обрабатывает события от AMI
func handleAMIEvent(event string) {
	// Логируем событие для отладки (можно убрать в продакшене)
	if strings.Contains(event, "Event: Newchannel") ||
		strings.Contains(event, "Event: Hangup") ||
		strings.Contains(event, "Event: Bridge") {
		log.Printf("📞 AMI Event: %s", getEventSummary(event))
	}

	// Детектируем начало вызова
	if strings.Contains(event, "Event: Newchannel") {
		extractCallInfo(event)
	}

	// Детектируем поднятие трубки
	if strings.Contains(event, "Event: Bridge") && strings.Contains(event, "BridgeState: Link") {
		startCallMonitoring()
	}

	// Детектируем состояние звонка
	if strings.Contains(event, "Event: Newstate") {
		handleCallState(event)
	}

	// Детектируем завершение вызова
	if strings.Contains(event, "Event: Hangup") {
		handleCallEnd(event)
	}
}

// extractCallInfo извлекает информацию о новом вызове
func extractCallInfo(event string) {
	channel := extractValue(event, "Channel: ")
	callerID := extractValue(event, "CallerIDNum: ")

	if channel != "" {
		activeMutex.Lock()
		activeCalls[channel] = &ActiveCall{
			Channel:    channel,
			CallerID:   callerID,
			State:      "Started",
			StartTime:  time.Now(),
			LastUpdate: time.Now(),
		}
		activeMutex.Unlock()

		log.Printf("📞 Обнаружен новый вызов: %s -> %s", callerID, channel)
	}
}

// handleCallState обрабатывает изменение состояния вызова
func handleCallState(event string) {
	channel := extractValue(event, "Channel: ")
	state := extractValue(event, "ChannelStateDesc: ")

	if channel != "" && state != "" {
		activeMutex.Lock()
		if call, exists := activeCalls[channel]; exists {
			call.State = state
			call.LastUpdate = time.Now()

			// Запускаем мониторинг при начале звонка
			if state == "Ringing" || state == "Up" {
				startCallMonitoring()
			}

			// Обновляем шаблон вызова для детектирования булькания
			updateCallPattern(channel, call.CallerID, state)
		}
		activeMutex.Unlock()
	}
}

// handleCallEnd обрабатывает завершение вызова
func handleCallEnd(event string) {
	channel := extractValue(event, "Channel: ")
	cause := extractValue(event, "Cause: ")

	if channel != "" {
		activeMutex.Lock()
		if call, exists := activeCalls[channel]; exists {
			// Анализируем причину завершения
			if cause != "0" && cause != "16" { // 0 - нормальное завершение, 16 - ответ
				problem := ProblemCall{
					Timestamp: time.Now().Format("2006-01-02 15:04:05"),
					Channel:   call.Channel,
					CallerID:  call.CallerID,
					Problem:   "Аномальное завершение вызова",
					Details:   fmt.Sprintf("Причина: %s", getCauseDescription(cause)),
					Severity:  "medium",
				}
				writeProblemCall(problem)
			}

			// Удаляем из активных вызовов
			delete(activeCalls, channel)
			log.Printf("📞 Вызов завершен: %s", channel)
		}
		activeMutex.Unlock()

		// Проверяем, есть ли еще активные вызовы
		checkActiveCalls()
	}
}

// updateCallPattern обновляет шаблоны вызовов для детектирования булькания
func updateCallPattern(channel, callerID, state string) {
	patternsMutex.Lock()
	defer patternsMutex.Unlock()

	key := callerID + ":" + channel
	pattern, exists := callPatterns[key]
	if !exists {
		pattern = &CallPattern{
			Channel:      channel,
			CallerID:     callerID,
			StateChanges: []time.Time{},
			LastReset:    time.Now(),
		}
		callPatterns[key] = pattern
	}

	// Сбрасываем счетчик если прошло больше часа
	if time.Since(pattern.LastReset) > time.Hour {
		pattern.RingCount = 0
		pattern.ShortCalls = 0
		pattern.StateChanges = []time.Time{}
		pattern.LastReset = time.Now()
	}

	if state != pattern.LastState {
		pattern.StateChanges = append(pattern.StateChanges, time.Now())
		pattern.LastState = state

		// Увеличиваем счетчик ringing состояний
		if state == "Ringing" {
			pattern.RingCount++

			// Проверяем булькание
			if pattern.RingCount >= config.BubblingThreshold {
				problem := ProblemCall{
					Timestamp: time.Now().Format("2006-01-02 15:04:05"),
					Channel:   channel,
					CallerID:  callerID,
					Problem:   "Обнаружено булькание",
					Details:   fmt.Sprintf("Количество быстрых звонков: %d", pattern.RingCount),
					Severity:  "critical",
				}
				writeProblemCall(problem)

				// Сбрасываем счетчик после детектирования
				pattern.RingCount = 0
			}
		}
	}
}

// startCallMonitoring запускает активный мониторинг
func startCallMonitoring() {
	if !monitoring {
		log.Println("🚀 Запуск активного мониторинга вызовов")
		monitoring = true

		// Запускаем интенсивный мониторинг на время вызова
		go intensiveMonitoring()
	}
}

// stopCallMonitoring останавливает активный мониторинг
func stopCallMonitoring() {
	if monitoring {
		log.Println("⏹️ Остановка активного мониторинга")
		monitoring = false
	}
}

// intensiveMonitoring интенсивный мониторинг во время активных вызовов
func intensiveMonitoring() {
	ticker := time.NewTicker(5 * time.Second) // Частые проверки во время вызовов
	defer ticker.Stop()

	for range ticker.C {
		if !monitoring {
			return
		}

		// Проверяем активные вызовы на проблемы
		checkActiveCallsForProblems()

		// Проверяем качество RTP
		checkRTPQuality()
	}
}

// checkActiveCalls проверяет наличие активных вызовов
func checkActiveCalls() {
	activeMutex.Lock()
	hasActiveCalls := len(activeCalls) > 0
	activeMutex.Unlock()

	if !hasActiveCalls && monitoring {
		// Нет активных вызовов - останавливаем мониторинг через 10 секунд
		time.AfterFunc(10*time.Second, func() {
			activeMutex.Lock()
			stillNoCalls := len(activeCalls) == 0
			activeMutex.Unlock()

			if stillNoCalls {
				stopCallMonitoring()
			}
		})
	}
}

// checkActiveCallsForProblems проверяет активные вызовы на проблемы
func checkActiveCallsForProblems() {
	activeMutex.Lock()
	defer activeMutex.Unlock()

	currentTime := time.Now()

	for channel, call := range activeCalls {
		// Проверяем долгое ожидание ответа
		if call.State == "Ringing" {
			ringDuration := currentTime.Sub(call.StartTime).Seconds()
			if ringDuration > float64(config.MaxRingDuration) {
				problem := ProblemCall{
					Timestamp: currentTime.Format("2006-01-02 15:04:05"),
					Channel:   channel,
					CallerID:  call.CallerID,
					Problem:   "Долгое ожидание ответа",
					Details:   fmt.Sprintf("Длительность: %.0f сек", ringDuration),
					Severity:  "medium",
				}
				writeProblemCall(problem)
			}
		}

		// Проверяем долгие вызовы
		if call.State == "Up" {
			callDuration := currentTime.Sub(call.StartTime).Seconds()
			if callDuration > float64(config.MaxCallDuration) {
				problem := ProblemCall{
					Timestamp: currentTime.Format("2006-01-02 15:04:05"),
					Channel:   channel,
					CallerID:  call.CallerID,
					Problem:   "Очень долгий вызов",
					Details:   fmt.Sprintf("Длительность: %.0f сек", callDuration),
					Severity:  "low",
				}
				writeProblemCall(problem)
			}
		}
	}
}

// checkRTPQuality проверяет качество RTP
func checkRTPQuality() {
	if !monitoring {
		return
	}

	qualityMetrics, err := getRTPQuality()
	if err != nil {
		return
	}

	for _, metric := range qualityMetrics {
		if metric.PacketLoss > config.PacketLossThreshold {
			problem := ProblemCall{
				Timestamp: time.Now().Format("2006-01-02 15:04:05"),
				Channel:   metric.Channel,
				CallerID:  "RTP Monitor",
				Problem:   "Высокие потери пакетов во время вызова",
				Details:   fmt.Sprintf("Потери: %.2f%%, MOS: %.2f", metric.PacketLoss, metric.MOS),
				Severity:  "high",
			}
			writeProblemCall(problem)
		}
	}
}

// getRTPQuality получает метрики качества RTP
func getRTPQuality() ([]QualityMetrics, error) {
	var metrics []QualityMetrics

	// Получаем статистику только если есть активные вызовы
	cmd := exec.Command("asterisk", "-rx", "core show channels")
	output, err := cmd.Output()
	if err != nil {
		return metrics, err
	}

	// Если нет активных каналов, возвращаем пустой список
	if strings.Contains(string(output), "0 active channels") {
		return metrics, nil
	}

	// Получаем RTP статистику только при наличии активных вызовов
	cmd = exec.Command("asterisk", "-rx", "rtp show stats")
	output, err = cmd.Output()
	if err != nil {
		return metrics, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "RTP Reader") {
			metrics = append(metrics, parseRTPLine(line))
		}
	}

	return metrics, nil
}

// parseRTPLine парсит строку RTP статистики
func parseRTPLine(line string) QualityMetrics {
	metric := QualityMetrics{
		Timestamp: time.Now(),
	}

	re := regexp.MustCompile(`loss:(\d+\.\d+)%`)
	if matches := re.FindStringSubmatch(line); len(matches) > 1 {
		metric.PacketLoss, _ = strconv.ParseFloat(matches[1], 64)
	}

	re = regexp.MustCompile(`jitter:(\d+\.\d+)`)
	if matches := re.FindStringSubmatch(line); len(matches) > 1 {
		metric.Jitter, _ = strconv.ParseFloat(matches[1], 64)
	}

	// Расчет MOS на основе потерь и джиттера
	metric.MOS = calculateMOS(metric.PacketLoss, metric.Jitter)

	return metric
}

// calculateMOS рассчитывает MOS score
func calculateMOS(packetLoss, jitter float64) float64 {
	baseMOS := 4.2
	lossPenalty := packetLoss * 0.1
	jitterPenalty := jitter * 0.001

	mos := baseMOS - lossPenalty - jitterPenalty
	if mos < 1.0 {
		return 1.0
	}
	if mos > 4.5 {
		return 4.5
	}
	return mos
}

// backgroundMonitoring фоновый мониторинг для редких проверок
func backgroundMonitoring() {
	// Запускаем обработку событий AMI
	go amiClient.processEvents()

	ticker := time.NewTicker(60 * time.Second) // Проверка раз в минуту
	defer ticker.Stop()

	for range ticker.C {
		// Проверяем SIP статус раз в 5 минут
		if time.Since(lastAsteriskCheck) > 5*time.Minute {
			checkSIPStatus()
			lastAsteriskCheck = time.Now()
		}

		// Очистка старых вызовов
		cleanupOldCalls()
	}
}

// checkSIPStatus проверяет статус SIP пиров
func checkSIPStatus() {
	sipStatus, err := getSIPStatus()
	if err != nil {
		log.Printf("Ошибка получения статуса SIP: %v", err)
		return
	}

	problems := analyzeSIPStatus(sipStatus)
	for _, problem := range problems {
		writeProblemCall(problem)
	}
}

// getSIPStatus получает статус SIP пиров
func getSIPStatus() ([]string, error) {
	cmd := exec.Command("asterisk", "-rx", "sip show peers")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return strings.Split(string(output), "\n"), nil
}

// analyzeSIPStatus анализирует статус SIP пиров
func analyzeSIPStatus(sipStatus []string) []ProblemCall {
	var problems []ProblemCall
	currentTime := time.Now().Format("2006-01-02 15:04:05")

	for _, line := range sipStatus {
		if strings.Contains(line, "UNREACHABLE") || strings.Contains(line, "UNKNOWN") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				problems = append(problems, ProblemCall{
					Timestamp: currentTime,
					Channel:   "SIP Peer",
					CallerID:  parts[0],
					Problem:   "SIP пир недоступен",
					Details:   line,
					Severity:  "high",
				})
			}
		}
	}

	return problems
}

// cleanupOldCalls очищает старые записи о вызовах
func cleanupOldCalls() {
	patternsMutex.Lock()
	defer patternsMutex.Unlock()

	currentTime := time.Now()
	for key, pattern := range callPatterns {
		if currentTime.Sub(pattern.LastReset) > 24*time.Hour {
			delete(callPatterns, key)
		}
	}
}

// monitorActiveCalls фоновый мониторинг для очистки старых вызовов
func monitorActiveCalls() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		activeMutex.Lock()
		currentTime := time.Now()

		for channel, call := range activeCalls {
			// Удаляем вызовы, которые не обновлялись более 5 минут
			if currentTime.Sub(call.LastUpdate) > 5*time.Minute {
				delete(activeCalls, channel)
				log.Printf("Удален зависший вызов: %s", channel)
			}
		}

		activeMutex.Unlock()
	}
}

// Вспомогательные функции
func extractValue(event, key string) string {
	if idx := strings.Index(event, key); idx != -1 {
		start := idx + len(key)
		end := strings.Index(event[start:], "\r")
		if end == -1 {
			end = len(event)
		} else {
			end = start + end
		}
		return strings.TrimSpace(event[start:end])
	}
	return ""
}

func getEventSummary(event string) string {
	eventType := extractValue(event, "Event: ")
	channel := extractValue(event, "Channel: ")
	callerID := extractValue(event, "CallerIDNum: ")

	return fmt.Sprintf("%s - Channel: %s, CallerID: %s", eventType, channel, callerID)
}

func getCauseDescription(cause string) string {
	causeMap := map[string]string{
		"1":  "Не назначенный номер",
		"3":  "Нет маршрута к назначению",
		"16": "Нормальное завершение",
		"17": "Занято",
		"18": "Таймаут ответа",
		"19": "Нет ответа",
		"21": "Вызов отклонен",
		"34": "Нет канала",
	}

	if desc, exists := causeMap[cause]; exists {
		return desc
	}
	return "Неизвестная причина: " + cause
}

func writeProblemCall(problem ProblemCall) {
	// Проверяем, не логировали ли мы уже эту проблему недавно
	problemKey := problem.Channel + ":" + problem.Problem
	if lastSeen, exists := problemHistory[problemKey]; exists {
		if time.Since(lastSeen) < 2*time.Minute {
			return // Пропускаем если уже видели эту проблему недавно
		}
	}
	problemHistory[problemKey] = time.Now()

	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Ошибка открытия файла логов: %v", err)
		return
	}
	defer file.Close()

	logEntry := fmt.Sprintf("[%s] [%s] ПРОБЛЕМА: %s | Канал: %s | CallerID: %s | Детали: %s\n",
		problem.Timestamp, problem.Severity, problem.Problem, problem.Channel, problem.CallerID, problem.Details)

	if _, err := file.WriteString(logEntry); err != nil {
		log.Printf("Ошибка записи в лог: %v", err)
	}

	fmt.Print(logEntry)
}

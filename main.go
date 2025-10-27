package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	logFile              = "/var/log/asterisk-monitor/calls_problem_online.log"
	cdrFile              = "/var/log/asterisk/cdr-csv/Master.csv"
	configFile           = "/etc/asterisk-monitor/config.conf"
	checkInterval        = 30 * time.Second
	qualityCheckInterval = 60 * time.Second
	cdrCheckInterval     = 300 * time.Second
	maxLogSize           = 100 * 1024 * 1024 // 100MB
)

// ProblemCall представляет проблемный вызов
type ProblemCall struct {
	Timestamp string
	Channel   string
	CallerID  string
	Problem   string
	Details   string
	Severity  string
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
	CheckInterval       int
	LogMaxSize          int
	LogMaxBackups       int
}

var (
	callPatterns      = make(map[string]*CallPattern)
	patternsMutex     = &sync.Mutex{}
	config            Config
	problemHistory    = make(map[string]time.Time)
	lastAsteriskCheck = time.Now()
	statsMutex        = &sync.Mutex{}
	monitoringStats   = struct {
		TotalCalls       int
		ProblemCalls     int
		LastProblemTime  time.Time
		StartTime        time.Time
	}{
		StartTime: time.Now(),
	}
)

func main() {
	fmt.Println("🚀 Asterisk Problem Calls Monitor запущен...")
	fmt.Printf("📊 Логи будут записываться в: %s\n", logFile)
	fmt.Printf("⏱️  Время запуска: %s\n", time.Now().Format("2006-01-02 15:04:05"))

	// Загружаем конфигурацию
	if err := loadConfig(); err != nil {
		log.Printf("⚠️  Ошибка загрузки конфигурации: %v. Используются значения по умолчанию.", err)
		setDefaultConfig()
	}

	// Создаем директорию для логов если не существует
	if err := os.MkdirAll("/var/log/asterisk-monitor", 0755); err != nil {
		log.Fatalf("❌ Ошибка создания директории: %v", err)
	}

	// Запускаем ротацию логов
	go logRotation()

	// Запускаем мониторинг Asterisk
	go monitorAsterisk()
	go monitorQuality()
	go analyzeCDR()
	go printStats()

	// Останавливаемся только при сигнале завершения
	fmt.Println("✅ Все сервисы мониторинга запущены")
	select {}
}

func setDefaultConfig() {
	config = Config{
		MaxRingDuration:     30,
		MaxCallDuration:     3600,
		BubblingThreshold:   3,
		PacketLossThreshold: 5.0,
		JitterThreshold:     50.0,
		ShortCallThreshold:  3,
		CheckInterval:       30,
		LogMaxSize:          100,
		LogMaxBackups:       3,
	}
}

func loadConfig() error {
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
		case "check_interval":
			config.CheckInterval, _ = strconv.Atoi(value)
		case "log_max_size":
			config.LogMaxSize, _ = strconv.Atoi(value)
		case "log_max_backups":
			config.LogMaxBackups, _ = strconv.Atoi(value)
		}
	}

	return nil
}

func monitorAsterisk() {
	interval := time.Duration(config.CheckInterval) * time.Second
	if interval == 0 {
		interval = checkInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		// Получаем статус каналов
		channels, err := getAsteriskChannels()
		if err != nil {
			log.Printf("❌ Ошибка получения статуса каналов: %v", err)
			continue
		}

		// Получаем статус SIP пиров (реже - раз в 2 минуты)
		var sipStatus []string
		if time.Since(lastAsteriskCheck) > 2*time.Minute {
			sipStatus, err = getSIPStatus()
			if err != nil {
				log.Printf("❌ Ошибка получения статуса SIP: %v", err)
			} else {
				lastAsteriskCheck = time.Now()
			}
		}

		// Анализируем каналы на проблемы
		problemCalls := analyzeChannels(channels, sipStatus)

		// Записываем проблемные вызовы в лог
		if len(problemCalls) > 0 {
			writeProblemCalls(problemCalls)
			updateStats(len(problemCalls))
		}

		// Логируем количество активных каналов для отладки
		if len(channels) > 1 { // Первая строка - заголовок
			log.Printf("📊 Активных каналов: %d", len(channels)-1)
		}
	}
}

func monitorQuality() {
	ticker := time.NewTicker(qualityCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		// Мониторинг качества RTP
		qualityMetrics, err := getRTPQuality()
		if err != nil {
			log.Printf("❌ Ошибка получения метрик качества: %v", err)
			continue
		}

		// Анализ качества связи
		problemCalls := analyzeQuality(qualityMetrics)
		if len(problemCalls) > 0 {
			writeProblemCalls(problemCalls)
			updateStats(len(problemCalls))
		}
	}
}

func getAsteriskChannels() ([]string, error) {
	cmd := exec.Command("asterisk", "-rx", "core show channels")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ошибка выполнения команды asterisk: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	var filteredLines []string
	
	for _, line := range lines {
		if strings.TrimSpace(line) != "" && !strings.Contains(line, "active channels") {
			filteredLines = append(filteredLines, line)
		}
	}
	
	return filteredLines, nil
}

func getSIPStatus() ([]string, error) {
	cmd := exec.Command("asterisk", "-rx", "sip show peers")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	return lines, nil
}

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

	// Получаем RTP статистику
	cmd = exec.Command("asterisk", "-rx", "rtp show stats")
	output, err = cmd.Output()
	if err != nil {
		return metrics, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "RTP") && (strings.Contains(line, "loss") || strings.Contains(line, "jitter")) {
			metric := parseRTPLine(line)
			if metric.PacketLoss > 0 || metric.Jitter > 0 {
				metrics = append(metrics, metric)
			}
		}
	}

	return metrics, nil
}

func parseRTPLine(line string) QualityMetrics {
	metric := QualityMetrics{
		Timestamp: time.Now(),
		Channel:   "unknown",
	}

	// Парсим потери пакетов
	re := regexp.MustCompile(`loss[=:]?\s*(\d+\.?\d*)%?`)
	if matches := re.FindStringSubmatch(line); len(matches) > 1 {
		metric.PacketLoss, _ = strconv.ParseFloat(matches[1], 64)
	}

	// Парсим джиттер
	re = regexp.MustCompile(`jitter[=:]?\s*(\d+\.?\d*)\s*ms?`)
	if matches := re.FindStringSubmatch(line); len(matches) > 1 {
		metric.Jitter, _ = strconv.ParseFloat(matches[1], 64)
	}

	// Парсим канал если есть
	re = regexp.MustCompile(`(SIP/\S+|PJSIP/\S+)`)
	if matches := re.FindStringSubmatch(line); len(matches) > 1 {
		metric.Channel = matches[1]
	}

	// Расчет MOS
	metric.MOS = calculateMOS(metric.PacketLoss, metric.Jitter)

	return metric
}

func calculateMOS(packetLoss, jitter float64) float64 {
	baseMOS := 4.4
	lossPenalty := packetLoss * 0.08
	jitterPenalty := jitter * 0.0008

	mos := baseMOS - lossPenalty - jitterPenalty
	if mos < 1.0 {
		return 1.0
	}
	if mos > 4.4 {
		return 4.4
	}
	return mos
}

func analyzeChannels(channels, sipStatus []string) []ProblemCall {
	var problemCalls []ProblemCall

	// Анализ статуса SIP пиров
	sipProblems := analyzeSIPStatus(sipStatus)
	problemCalls = append(problemCalls, sipProblems...)

	// Анализ активных каналов
	activeCallCount := 0
	for _, line := range channels {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Считаем активные вызовы
		if isActiveCall(line) {
			activeCallCount++
		}

		// Проверяем различные типы проблем
		if problems := detectProblems(line); len(problems) > 0 {
			problemCalls = append(problemCalls, problems...)
		}
	}

	// Обновляем статистику
	statsMutex.Lock()
	monitoringStats.TotalCalls += activeCallCount
	statsMutex.Unlock()

	return problemCalls
}

func isActiveCall(line string) bool {
	return strings.Contains(line, "Up") || strings.Contains(line, "Ringing") || 
		   strings.Contains(line, "Dial") || strings.Contains(line, "Answer")
}

func analyzeSIPStatus(sipStatus []string) []ProblemCall {
	var problems []ProblemCall
	currentTime := time.Now().Format("2006-01-02 15:04:05")

	for _, line := range sipStatus {
		if strings.Contains(line, "UNREACHABLE") {
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

		if strings.Contains(line, "LAGGED") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				problems = append(problems, ProblemCall{
					Timestamp: currentTime,
					Channel:   "SIP Peer",
					CallerID:  parts[0],
					Problem:   "SIP пир с задержками",
					Details:   fmt.Sprintf("Задержка: %s", line),
					Severity:  "medium",
				})
			}
		}

		if strings.Contains(line, "UNKNOWN") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				problems = append(problems, ProblemCall{
					Timestamp: currentTime,
					Channel:   "SIP Peer",
					CallerID:  parts[0],
					Problem:   "SIP пир в неизвестном состоянии",
					Details:   line,
					Severity:  "medium",
				})
			}
		}
	}

	return problems
}

func detectProblems(channelInfo string) []ProblemCall {
	var problems []ProblemCall
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	channel := extractChannel(channelInfo)
	callerID := extractCallerID(channelInfo)

	// Обновляем шаблон вызова для детектирования булькания
	updateCallPattern(channel, callerID, channelInfo)

	// Детектор "булькания"
	if bubbling := detectBubbling(channel, callerID); bubbling != nil {
		problems = append(problems, *bubbling)
	}

	// Детектор долгого ожидания ответа
	if strings.Contains(channelInfo, "Ringing") || strings.Contains(channelInfo, "RINGING") {
		if duration := extractDuration(channelInfo); duration > config.MaxRingDuration {
			problems = append(problems, ProblemCall{
				Timestamp: currentTime,
				Channel:   channel,
				CallerID:  callerID,
				Problem:   "Долгое ожидание ответа",
				Details:   fmt.Sprintf("Длительность: %d сек (>%d)", duration, config.MaxRingDuration),
				Severity:  "medium",
			})
		}
	}

	// Детектор заблокированных каналов
	if strings.Contains(channelInfo, "Busy") || strings.Contains(channelInfo, "BUSY") {
		problems = append(problems, ProblemCall{
			Timestamp: currentTime,
			Channel:   channel,
			CallerID:  callerID,
			Problem:   "Канал занят",
			Details:   "Абонент занят",
			Severity:  "low",
		})
	}

	// Детектор неудачных вызовов
	if strings.Contains(channelInfo, "Failed") || strings.Contains(channelInfo, "FAILED") || 
	   strings.Contains(channelInfo, "Congestion") || strings.Contains(channelInfo, "CONGESTION") {
		problems = append(problems, ProblemCall{
			Timestamp: currentTime,
			Channel:   channel,
			CallerID:  callerID,
			Problem:   "Неудачный вызов",
			Details:   "Вызов не удался",
			Severity:  "high",
		})
	}

	// Детектор долгих вызовов
	if strings.Contains(channelInfo, "Up") {
		duration := extractDuration(channelInfo)
		if duration > config.MaxCallDuration {
			problems = append(problems, ProblemCall{
				Timestamp: currentTime,
				Channel:   channel,
				CallerID:  callerID,
				Problem:   "Очень долгий вызов",
				Details:   fmt.Sprintf("Длительность: %d сек (>%d)", duration, config.MaxCallDuration),
				Severity:  "medium",
			})
		}
	}

	return problems
}

func updateCallPattern(channel, callerID, channelInfo string) {
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

	currentState := extractState(channelInfo)
	if currentState != pattern.LastState {
		pattern.StateChanges = append(pattern.StateChanges, time.Now())
		pattern.LastState = currentState

		// Увеличиваем счетчик ringing состояний
		if currentState == "RINGING" {
			pattern.RingCount++
		}
	}
}

func detectBubbling(channel, callerID string) *ProblemCall {
	patternsMutex.Lock()
	defer patternsMutex.Unlock()

	key := callerID + ":" + channel
	pattern, exists := callPatterns[key]
	if !exists {
		return nil
	}

	currentTime := time.Now().Format("2006-01-02 15:04:05")

	// Детектирование булькания по количеству ringing состояний
	if pattern.RingCount >= config.BubblingThreshold {
		// Сбрасываем счетчик после детектирования
		pattern.RingCount = 0
		return &ProblemCall{
			Timestamp: currentTime,
			Channel:   channel,
			CallerID:  callerID,
			Problem:   "Обнаружено булькание",
			Details:   fmt.Sprintf("Количество быстрых звонков: %d", config.BubblingThreshold),
			Severity:  "critical",
		}
	}

	return nil
}

func analyzeQuality(metrics []QualityMetrics) []ProblemCall {
	var problems []ProblemCall
	currentTime := time.Now().Format("2006-01-02 15:04:05")

	for _, metric := range metrics {
		// Проверка потерь пакетов
		if metric.PacketLoss > config.PacketLossThreshold {
			problems = append(problems, ProblemCall{
				Timestamp: currentTime,
				Channel:   metric.Channel,
				CallerID:  "RTP Stream",
				Problem:   "Высокие потери пакетов",
				Details:   fmt.Sprintf("Потери: %.2f%% (>%.1f%%), MOS: %.2f", 
					metric.PacketLoss, config.PacketLossThreshold, metric.MOS),
				Severity:  "high",
			})
		}

		// Проверка джиттера
		if metric.Jitter > config.JitterThreshold {
			problems = append(problems, ProblemCall{
				Timestamp: currentTime,
				Channel:   metric.Channel,
				CallerID:  "RTP Stream",
				Problem:   "Высокий джиттер",
				Details:   fmt.Sprintf("Джиттер: %.2f мс (>%.1f мс), MOS: %.2f", 
					metric.Jitter, config.JitterThreshold, metric.MOS),
				Severity:  "medium",
			})
		}

		// Проверка качества голоса
		if metric.MOS < 3.0 {
			problems = append(problems, ProblemCall{
				Timestamp: currentTime,
				Channel:   metric.Channel,
				CallerID:  "RTP Stream",
				Problem:   "Плохое качество голоса",
				Details:   fmt.Sprintf("MOS: %.2f (требуется >3.0)", metric.MOS),
				Severity:  "high",
			})
		}
	}

	return problems
}

func analyzeCDR() {
	ticker := time.NewTicker(cdrCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		file, err := os.Open(cdrFile)
		if err != nil {
			log.Printf("⚠️  Ошибка открытия CDR файла: %v", err)
			continue
		}
		defer file.Close()

		reader := csv.NewReader(file)
		records, err := reader.ReadAll()
		if err != nil {
			log.Printf("⚠️  Ошибка чтения CDR: %v", err)
			continue
		}

		// Анализ последних записей CDR
		analyzeShortCalls(records)
	}
}

func analyzeShortCalls(records [][]string) {
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	shortCallThreshold := time.Duration(config.ShortCallThreshold) * time.Second

	shortCallsCount := 0
	for _, record := range records {
		if len(record) < 14 {
			continue
		}

		// Парсим длительность вызова
		duration, err := time.ParseDuration(record[9] + "s")
		if err != nil {
			continue
		}

		// Детектирование коротких вызовов
		if duration <= shortCallThreshold && record[12] == "ANSWERED" {
			shortCallsCount++
			problem := ProblemCall{
				Timestamp: currentTime,
				Channel:   record[1],
				CallerID:  record[2],
				Problem:   "Очень короткий вызов",
				Details:   fmt.Sprintf("Длительность: %v, Назначение: %s", duration, record[4]),
				Severity:  "medium",
			}
			writeProblemCalls([]ProblemCall{problem})
		}
	}

	if shortCallsCount > 0 {
		log.Printf("📞 Обнаружено коротких вызовов: %d", shortCallsCount)
	}
}

func extractChannel(line string) string {
	parts := strings.Fields(line)
	if len(parts) > 0 {
		return parts[0]
	}
	return "unknown"
}

func extractCallerID(line string) string {
	// Ищем номер в формате <123>
	if start := strings.Index(line, "<"); start != -1 {
		if end := strings.Index(line[start:], ">"); end != -1 {
			return line[start+1 : start+end]
		}
	}

	// Ищем номер телефона
	re := regexp.MustCompile(`(\+\d{11}|\d{6,10})`)
	if matches := re.FindStringSubmatch(line); len(matches) > 0 {
		return matches[0]
	}

	return "unknown"
}

func extractDuration(line string) int {
	// Формат: 1h 2m 3s
	re := regexp.MustCompile(`(\d+)h\s*(\d+)m\s*(\d+)s`)
	if matches := re.FindStringSubmatch(line); len(matches) == 4 {
		h, _ := strconv.Atoi(matches[1])
		m, _ := strconv.Atoi(matches[2])
		s, _ := strconv.Atoi(matches[3])
		return h*3600 + m*60 + s
	}

	// Формат: 2m 3s
	re = regexp.MustCompile(`(\d+)m\s*(\d+)s`)
	if matches := re.FindStringSubmatch(line); len(matches) == 3 {
		m, _ := strconv.Atoi(matches[1])
		s, _ := strconv.Atoi(matches[2])
		return m*60 + s
	}

	// Формат: 45s
	re = regexp.MustCompile(`(\d+)s`)
	if matches := re.FindStringSubmatch(line); len(matches) == 2 {
		s, _ := strconv.Atoi(matches[1])
		return s
	}

	return 0
}

func extractState(line string) string {
	states := []string{"RINGING", "UP", "BUSY", "FAILED", "CONGESTION", "ANSWERED", "DIALING"}
	for _, state := range states {
		if strings.Contains(strings.ToUpper(line), state) {
			return state
		}
	}
	return "UNKNOWN"
}

func writeProblemCalls(calls []ProblemCall) {
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("❌ Ошибка открытия файла логов: %v", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	for _, call := range calls {
		// Проверяем, не логировали ли мы уже эту проблему недавно
		problemKey := call.Channel + ":" + call.Problem
		if lastSeen, exists := problemHistory[problemKey]; exists {
			if time.Since(lastSeen) < 2*time.Minute {
				continue
			}
		}

		problemHistory[problemKey] = time.Now()

		logEntry := fmt.Sprintf("[%s] [%s] ПРОБЛЕМА: %s | Канал: %s | CallerID: %s | Детали: %s\n",
			call.Timestamp, call.Severity, call.Problem, call.Channel, call.CallerID, call.Details)

		_, err := writer.WriteString(logEntry)
		if err != nil {
			log.Printf("❌ Ошибка записи в лог: %v", err)
		}

		// Выводим в консоль для отладки
		fmt.Print(logEntry)
	}

	writer.Flush()
}

func logRotation() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		info, err := os.Stat(logFile)
		if err != nil {
			continue
		}

		if info.Size() > int64(config.LogMaxSize*1024*1024) {
			rotateLogFile()
		}
	}
}

func rotateLogFile() {
	backupPath := fmt.Sprintf("%s.1", logFile)
	os.Rename(logFile, backupPath)
	log.Printf("🔄 Файл логов ротирован: %s -> %s", logFile, backupPath)
}

func updateStats(problemsCount int) {
	statsMutex.Lock()
	defer statsMutex.Unlock()

	monitoringStats.ProblemCalls += problemsCount
	monitoringStats.LastProblemTime = time.Now()
}

func printStats() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		statsMutex.Lock()
		uptime := time.Since(monitoringStats.StartTime)
		stats := monitoringStats
		statsMutex.Unlock()

		log.Printf("📈 Статистика: Запуск: %v, Всего вызовов: %d, Проблем: %d, Аптайм: %v",
			stats.StartTime.Format("15:04:05"), stats.TotalCalls, stats.ProblemCalls, uptime.Truncate(time.Second))
	}
}
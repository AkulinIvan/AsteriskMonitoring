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
	logFile      = "/var/log/asterisk-monitor/calls_problem_online.log"
	cdrFile      = "/var/log/asterisk/cdr-csv/Master.csv"
	configFile   = "/etc/asterisk-monitor/config.conf"
	historyFile  = "/var/log/asterisk-monitor/call_history.db"
	checkInterval = 30 * time.Second
	qualityCheckInterval = 60 * time.Second
	cdrCheckInterval = 300 * time.Second
)

// ProblemCall представляет проблемный вызов
type ProblemCall struct {
	Timestamp string
	Channel   string
	CallerID  string
	Problem   string
	Details   string
	Severity  string // "low", "medium", "high", "critical"
}

// QualityMetrics представляет метрики качества связи
type QualityMetrics struct {
	Channel      string
	PacketLoss   float64
	Jitter       float64
	Latency      int
	MOS          float64
	RTPErrors    int
	Timestamp    time.Time
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
	MaxRingDuration    int
	MaxCallDuration    int
	BubblingThreshold  int
	PacketLossThreshold float64
	JitterThreshold    float64
	ShortCallThreshold int
	CheckInterval      int
}

var (
	callPatterns   = make(map[string]*CallPattern)
	patternsMutex  = &sync.Mutex{}
	config         Config
	problemHistory = make(map[string]time.Time)
	lastAsteriskCheck time.Time
)

func main() {
	fmt.Println("Asterisk Problem Calls Monitor запущен...")
	fmt.Printf("Логи будут записываться в: %s\n", logFile)
	fmt.Printf("Интервал проверки: %v\n", checkInterval)

	// Загружаем конфигурацию
	if err := loadConfig(); err != nil {
		log.Printf("Ошибка загрузки конфигурации: %v. Используются значения по умолчанию.", err)
		config = Config{
			MaxRingDuration:    30,
			MaxCallDuration:    3600,
			BubblingThreshold:  3,
			PacketLossThreshold: 5.0,
			JitterThreshold:    50.0,
			ShortCallThreshold: 3,
			CheckInterval:      30,
		}
	}

	// Создаем директорию для логов если не существует
	if err := os.MkdirAll("/var/log/asterisk-monitor", 0755); err != nil {
		log.Fatalf("Ошибка создания директории: %v", err)
	}

	// Открываем файл логов для записи
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Ошибка открытия файла логов: %v", err)
	}
	defer file.Close()

	// Запускаем мониторинг Asterisk
	go monitorAsterisk(file)
	go monitorQuality()
	go analyzeCDR()

	// Останавливаемся только при сигнале завершения
	select {}
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
		case "check_interval":
			config.CheckInterval, _ = strconv.Atoi(value)
		}
	}

	return nil
}

func monitorAsterisk(logFile *os.File) {
	interval := time.Duration(config.CheckInterval) * time.Second
	if interval == 0 {
		interval = checkInterval
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for range ticker.C {
		log.Printf("Выполняется проверка Asterisk...")
		// Получаем статус каналов
		channels, err := getAsteriskChannels()
		if err != nil {
			log.Printf("Ошибка получения статуса каналов: %v", err)
			continue
		}

		// Получаем статус SIP пиров
		var sipStatus []string
		if time.Since(lastAsteriskCheck) > 2*time.Minute {
			sipStatus, err = getSIPStatus()
			if err != nil {
				log.Printf("Ошибка получения статуса SIP: %v", err)
			}
			lastAsteriskCheck = time.Now()
		}

		// Анализируем каналы на проблемы
		problemCalls := analyzeChannels(channels, sipStatus)

		// Записываем проблемные вызовы в лог
		if len(problemCalls) > 0 {
			writeProblemCalls(logFile, problemCalls)
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
			log.Printf("Ошибка получения метрик качества: %v", err)
			continue
		}

		// Анализ качества связи
		problemCalls := analyzeQuality(qualityMetrics)
		if len(problemCalls) > 0 {
			file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				writeProblemCalls(file, problemCalls)
				file.Close()
			}
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
		if strings.TrimSpace(line) != "" {
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

func parseRTPLine(line string) QualityMetrics {
	// Пример парсинга строки RTP статистики
	// Это упрощенный парсер - в реальности нужно адаптировать под ваш формат
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

func calculateMOS(packetLoss, jitter float64) float64 {
	// Упрощенный расчет MOS score
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

func analyzeChannels(channels, sipStatus []string) []ProblemCall {
	var problemCalls []ProblemCall

	// Анализ статуса SIP пиров
	sipProblems := analyzeSIPStatus(sipStatus)
	problemCalls = append(problemCalls, sipProblems...)

	// Анализ активных каналов
	for _, line := range channels {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Проверяем различные типы проблем
		if problems := detectProblems(line); problems != nil {
			problemCalls = append(problemCalls, problems...)
		}
	}

	return problemCalls
}

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

		if strings.Contains(line, "LAGGED") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				problems = append(problems, ProblemCall{
					Timestamp: currentTime,
					Channel:   "SIP Peer",
					CallerID:  parts[0],
					Problem:   "SIP пир с задержками",
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
	if strings.Contains(channelInfo, "RINGING") {
		if duration := extractDuration(channelInfo); duration > config.MaxRingDuration {
			problems = append(problems, ProblemCall{
				Timestamp: currentTime,
				Channel:   channel,
				CallerID:  callerID,
				Problem:   "Долгое ожидание ответа",
				Details:   fmt.Sprintf("Длительность: %d сек, %s", duration, channelInfo),
				Severity:  "medium",
			})
		}
	}

	// Детектор заблокированных каналов
	if strings.Contains(channelInfo, "BUSY") {
		problems = append(problems, ProblemCall{
			Timestamp: currentTime,
			Channel:   channel,
			CallerID:  callerID,
			Problem:   "Канал занят",
			Details:   channelInfo,
			Severity:  "low",
		})
	}

	// Детектор неудачных вызовов
	if strings.Contains(channelInfo, "FAILED") || strings.Contains(channelInfo, "CONGESTION") {
		problems = append(problems, ProblemCall{
			Timestamp: currentTime,
			Channel:   channel,
			CallerID:  callerID,
			Problem:   "Неудачный вызов",
			Details:   channelInfo,
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
				Details:   fmt.Sprintf("Длительность: %d сек, %s", duration, channelInfo),
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

	// Детектирование по частым изменениям состояния
	if len(pattern.StateChanges) >= 5 {
		recentChanges := 0
		for i := len(pattern.StateChanges) - 1; i >= 0; i-- {
			if time.Since(pattern.StateChanges[i]) <= 2*time.Minute {
				recentChanges++
			}
		}

		if recentChanges >= 5 {
			pattern.StateChanges = []time.Time{}
			return &ProblemCall{
				Timestamp: currentTime,
				Channel:   channel,
				CallerID:  callerID,
				Problem:   "Частые изменения состояния канала",
				Details:   "Возможное булькание или нестабильность связи",
				Severity:  "high",
			}
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
				Details:   fmt.Sprintf("Потери: %.2f%%, MOS: %.2f", metric.PacketLoss, metric.MOS),
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
				Details:   fmt.Sprintf("Джиттер: %.2f мс, MOS: %.2f", metric.Jitter, metric.MOS),
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
			log.Printf("Ошибка открытия CDR файла: %v", err)
			continue
		}
		defer file.Close()

		reader := csv.NewReader(file)
		records, err := reader.ReadAll()
		if err != nil {
			log.Printf("Ошибка чтения CDR: %v", err)
			continue
		}

		// Анализ последних записей CDR
		analyzeShortCalls(records)
	}
}

func analyzeShortCalls(records [][]string) {
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	shortCallThreshold := time.Duration(config.ShortCallThreshold) * time.Second

	for _, record := range records {
		if len(record) < 12 {
			continue
		}

		// Парсим длительность вызова
		duration, err := time.ParseDuration(record[9] + "s")
		if err != nil {
			continue
		}

		// Детектирование коротких вызовов
		if duration <= shortCallThreshold && record[12] == "ANSWERED" {
			problem := ProblemCall{
				Timestamp: currentTime,
				Channel:   record[1],
				CallerID:  record[2],
				Problem:   "Очень короткий вызов",
				Details:   fmt.Sprintf("Длительность: %v, Причина: %s", duration, record[13]),
				Severity:  "medium",
			}

			// Записываем в лог
			file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				writeProblemCalls(file, []ProblemCall{problem})
				file.Close()
			}
		}
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
	re := regexp.MustCompile(`(\+?[0-9]+)`)
	matches := re.FindStringSubmatch(line)
	if len(matches) > 0 {
		return matches[0]
	}

	if strings.Contains(line, "<") && strings.Contains(line, ">") {
		start := strings.Index(line, "<")
		end := strings.Index(line, ">")
		if start < end {
			return line[start+1 : end]
		}
	}
	return "unknown"
}

func extractDuration(line string) int {
	re := regexp.MustCompile(`(\d+)h\s*(\d+)m\s*(\d+)s`)
	matches := re.FindStringSubmatch(line)
	if len(matches) == 4 {
		hours, _ := strconv.Atoi(matches[1])
		minutes, _ := strconv.Atoi(matches[2])
		seconds, _ := strconv.Atoi(matches[3])
		return hours*3600 + minutes*60 + seconds
	}

	re = regexp.MustCompile(`(\d+)m\s*(\d+)s`)
	matches = re.FindStringSubmatch(line)
	if len(matches) == 3 {
		minutes, _ := strconv.Atoi(matches[1])
		seconds, _ := strconv.Atoi(matches[2])
		return minutes*60 + seconds
	}

	re = regexp.MustCompile(`(\d+)s`)
	matches = re.FindStringSubmatch(line)
	if len(matches) == 2 {
		seconds, _ := strconv.Atoi(matches[1])
		return seconds
	}

	return 0
}

func extractState(line string) string {
	states := []string{"RINGING", "UP", "BUSY", "FAILED", "CONGESTION", "ANSWERED"}
	for _, state := range states {
		if strings.Contains(line, state) {
			return state
		}
	}
	return "UNKNOWN"
}

func writeProblemCalls(logFile *os.File, calls []ProblemCall) {
	writer := bufio.NewWriter(logFile)

	for _, call := range calls {
		// Проверяем, не логировали ли мы уже эту проблему недавно
		problemKey := call.Channel + ":" + call.Problem
		if lastSeen, exists := problemHistory[problemKey]; exists {
			if time.Since(lastSeen) < 2*time.Minute {
				continue // Пропускаем если уже видели эту проблему недавно
			}
		}

		problemHistory[problemKey] = time.Now()

		logEntry := fmt.Sprintf("[%s] [%s] ПРОБЛЕМА: %s | Канал: %s | CallerID: %s | Детали: %s\n",
			call.Timestamp, call.Severity, call.Problem, call.Channel, call.CallerID, call.Details)

		_, err := writer.WriteString(logEntry)
		if err != nil {
			log.Printf("Ошибка записи в лог: %v", err)
		}

		// Также выводим в консоль для отладки
		fmt.Print(logEntry)
	}

	writer.Flush()
}
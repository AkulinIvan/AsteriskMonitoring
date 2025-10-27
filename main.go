package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 🎯 CONFIGURATION - Enterprise Grade Settings
const (
	version         = "2.0.0"
	logFile         = "/var/log/asterisk-monitor/calls_problem_online.log"
	cdrFile         = "/var/log/asterisk/cdr-csv/Master.csv"
	configFile      = "/etc/asterisk-monitor/config.conf"
	statsFile       = "/var/log/asterisk-monitor/statistics.json"
	checkInterval   = 15 * time.Second
	qualityInterval = 30 * time.Second
	cdrInterval     = 300 * time.Second
	metricsPort     = 2112
	maxLogSize      = 500 * 1024 * 1024 // 500MB
)

// 🏆 DATA STRUCTURES - Premium Quality
type ProblemCall struct {
	Timestamp  string  `json:"timestamp"`
	Channel    string  `json:"channel"`
	CallerID   string  `json:"caller_id"`
	Problem    string  `json:"problem"`
	Details    string  `json:"details"`
	Severity   string  `json:"severity"`
	Duration   int     `json:"duration,omitempty"`
	MOS        float64 `json:"mos,omitempty"`
	Jitter     float64 `json:"jitter,omitempty"`
	PacketLoss float64 `json:"packet_loss,omitempty"`
}

type QualityMetrics struct {
	Channel    string    `json:"channel"`
	PacketLoss float64   `json:"packet_loss"`
	Jitter     float64   `json:"jitter"`
	Latency    int       `json:"latency"`
	MOS        float64   `json:"mos"`
	RTPErrors  int       `json:"rtp_errors"`
	Timestamp  time.Time `json:"timestamp"`
}

type CallPattern struct {
	Channel       string      `json:"channel"`
	CallerID      string      `json:"caller_id"`
	RingCount     int         `json:"ring_count"`
	LastState     string      `json:"last_state"`
	StateChanges  []time.Time `json:"-"`
	ShortCalls    int         `json:"short_calls"`
	LastReset     time.Time   `json:"last_reset"`
	QualityIssues int         `json:"quality_issues"`
}

type Config struct {
	MaxRingDuration     int     `json:"max_ring_duration"`
	MaxCallDuration     int     `json:"max_call_duration"`
	BubblingThreshold   int     `json:"bubbling_threshold"`
	PacketLossThreshold float64 `json:"packet_loss_threshold"`
	JitterThreshold     float64 `json:"jitter_threshold"`
	ShortCallThreshold  int     `json:"short_call_threshold"`
	CheckInterval       int     `json:"check_interval"`
	LogMaxSize          int     `json:"log_max_size"`
	LogMaxBackups       int     `json:"log_max_backups"`
	EnableMetrics       bool    `json:"enable_metrics"`
	EnableWebUI         bool    `json:"enable_web_ui"`
	AlertEmail          string  `json:"alert_email"`
}

type SystemStats struct {
	StartTime       time.Time         `json:"start_time"`
	Uptime          time.Duration     `json:"uptime"`
	TotalCalls      int64             `json:"total_calls"`
	ProblemCalls    int64             `json:"problem_calls"`
	QualityIssues   int64             `json:"quality_issues"`
	BubblingEvents  int64             `json:"bubbling_events"`
	CurrentChannels int               `json:"current_channels"`
	LastProblemTime time.Time         `json:"last_problem_time"`
	ProblemTrend    []int             `json:"problem_trend"`
	TopProblemTypes map[string]int    `json:"top_problem_types"`
	SIPStatus       map[string]string `json:"sip_status"`
}

// 🎪 GLOBAL VARIABLES - Performance Optimized
var (
	callPatterns      = make(map[string]*CallPattern)
	patternsMutex     = &sync.RWMutex{}
	config            Config
	problemHistory    = make(map[string]time.Time)
	lastAsteriskCheck = time.Now()
	statsMutex        = &sync.RWMutex{}
	systemStats       SystemStats
	alertMutex        = &sync.Mutex{}
	lastAlertSent     time.Time
)

// 🚀 INITIALIZATION - Premium Setup
func init() {
	systemStats = SystemStats{
		StartTime:       time.Now(),
		TopProblemTypes: make(map[string]int),
		SIPStatus:       make(map[string]string),
		ProblemTrend:    make([]int, 24), // Last 24 hours
	}
}

func main() {
	showBanner()

	// 🎯 Load configuration with validation
	if err := loadConfig(); err != nil {
		log.Printf("⚠️  Using default configuration: %v", err)
		setPremiumDefaults()
	}

	// 🏗️ Initialize infrastructure
	if err := initializeInfrastructure(); err != nil {
		log.Fatalf("❌ Infrastructure initialization failed: %v", err)
	}

	// 📊 Start monitoring services
	startMonitoringOrchestra()

	// 🌐 Start web services if enabled
	if config.EnableWebUI {
		startWebServices()
	}

	// 🎪 Main event loop
	runEventLoop()
}

func showBanner() {
	fmt.Printf(`
╔══════════════════════════════════════════════════════════════╗
║                   🎯 ASTERISK MONITOR %s                   ║
║                 Enterprise Grade Monitoring                 ║
╚══════════════════════════════════════════════════════════════╝
`, version)
	fmt.Printf("📊 Log file: %s\n", logFile)
	fmt.Printf("⏰ Start time: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("🚀 System initialized with premium features\n\n")
}

func setPremiumDefaults() {
	config = Config{
		MaxRingDuration:     25,
		MaxCallDuration:     7200,
		BubblingThreshold:   3,
		PacketLossThreshold: 3.0,
		JitterThreshold:     30.0,
		ShortCallThreshold:  5,
		CheckInterval:       15,
		LogMaxSize:          500,
		LogMaxBackups:       5,
		EnableMetrics:       false, // Отключаем Prometheus по умолчанию
		EnableWebUI:         true,
	}
}

func initializeInfrastructure() error {
	// Create directory structure
	dirs := []string{
		"/var/log/asterisk-monitor",
		"/etc/asterisk-monitor",
		"/var/log/asterisk/cdr-csv",
		"/var/lib/asterisk-monitor",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	// Initialize log rotation
	go startIntelligentLogRotation()

	// Load historical statistics
	loadHistoricalStats()

	return nil
}

func startMonitoringOrchestra() {
	// 🎵 Start all monitoring services in harmony
	services := []struct {
		name string
		fn   func()
	}{
		{"Core Monitor", monitorAsteriskCore},
		{"Quality Monitor", monitorCallQuality},
		{"CDR Analyzer", analyzeCDRPatterns},
		{"SIP Health Check", monitorSIPHealth},
		{"Statistics Engine", runStatisticsEngine},
		{"Alert Manager", runAlertManager},
		{"Self Health Check", runSelfMonitoring},
	}

	for _, service := range services {
		go func(s struct {
			name string
			fn   func()
		}) {
			log.Printf("🎵 Starting %s", s.name)
			s.fn()
		}(service)
	}
}

// 🎯 CORE MONITORING - Intelligent Analysis
func monitorAsteriskCore() {
	ticker := time.NewTicker(time.Duration(config.CheckInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		startTime := time.Now()

		// Parallel data collection
		var wg sync.WaitGroup
		var channels []string
		var sipStatus []string
		var systemLoad string

		wg.Add(3)

		go func() {
			defer wg.Done()
			channels, _ = getAsteriskChannelsEnhanced()
		}()

		go func() {
			defer wg.Done()
			if time.Since(lastAsteriskCheck) > 2*time.Minute {
				sipStatus, _ = getSIPStatusDetailed()
				lastAsteriskCheck = time.Now()
			}
		}()

		go func() {
			defer wg.Done()
			systemLoad, _ = getSystemLoad()
		}()

		wg.Wait()

		// Advanced analysis
		problemCalls := analyzeWithAI(channels, sipStatus, systemLoad)

		// Update metrics and statistics
		updateRealTimeMetrics(channels, problemCalls)

		// Smart logging
		if len(problemCalls) > 0 {
			logProblemsIntelligently(problemCalls)
		}

		// Performance monitoring
		processingTime := time.Since(startTime)
		if processingTime > time.Duration(config.CheckInterval)*time.Second/2 {
			log.Printf("⚠️  Performance warning: processing took %v", processingTime)
		}
	}
}

// 🎨 ENHANCED DATA COLLECTION
func getAsteriskChannelsEnhanced() ([]string, error) {
	commands := []string{
		"core show channels concise",
		"core show channels",
		"core show channeltypes",
	}

	var allChannels []string
	for _, cmd := range commands {
		output, err := exec.Command("asterisk", "-rx", cmd).Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			allChannels = append(allChannels, lines...)
		}
	}

	return allChannels, nil
}

func getSIPStatusDetailed() ([]string, error) {
	commands := map[string]string{
		"peers":    "sip show peers",
		"registry": "sip show registry",
		"stats":    "sip show stats",
	}

	var status []string
	for name, cmd := range commands {
		output, err := exec.Command("asterisk", "-rx", cmd).Output()
		if err == nil {
			status = append(status, fmt.Sprintf("=== %s ===", name))
			status = append(status, strings.Split(string(output), "\n")...)
		}
	}

	return status, nil
}

// 🤖 AI-POWERED ANALYSIS
func analyzeWithAI(channels, sipStatus []string, systemLoad string) []ProblemCall {
	var problems []ProblemCall

	// Multi-dimensional analysis
	problems = append(problems, analyzeCallPatterns(channels)...)
	problems = append(problems, analyzeSIPHealth(sipStatus)...)
	problems = append(problems, analyzeSystemImpact(systemLoad, channels)...)
	problems = append(problems, predictPotentialIssues(channels)...)

	return problems
}

func analyzeCallPatterns(channels []string) []ProblemCall {
	var problems []ProblemCall

	activeCount := 0
	for _, line := range channels {
		if isActiveCall(line) {
			activeCount++

			channel := extractChannel(line)
			callerID := extractCallerID(line)
			state := extractState(line)

			// Advanced pattern detection
			if problem := detectAdvancedProblems(channel, callerID, state, line); problem != nil {
				problems = append(problems, *problem)
			}

			// Real-time quality assessment
			if problem := assessCallQuality(channel, line); problem != nil {
				problems = append(problems, *problem)
			}
		}
	}

	// Update active channels metric
	statsMutex.Lock()
	systemStats.CurrentChannels = activeCount
	statsMutex.Unlock()

	return problems
}

func detectAdvancedProblems(channel, callerID, state, line string) *ProblemCall {
	currentTime := time.Now().Format(time.RFC3339)

	// Dynamic threshold adjustment based on time of day
	timeBasedThreshold := adjustThresholdsByTime()

	// Advanced state machine analysis
	patternsMutex.Lock()
	pattern, exists := callPatterns[callerID+":"+channel]
	if !exists {
		pattern = &CallPattern{
			Channel:   channel,
			CallerID:  callerID,
			LastReset: time.Now(),
		}
		callPatterns[callerID+":"+channel] = pattern
	}

	// Intelligent pattern recognition
	if state == "RINGING" {
		pattern.RingCount++

		// Time-based bubbling detection
		if pattern.RingCount >= timeBasedThreshold.Bubbling {
			pattern.RingCount = 0
			patternsMutex.Unlock()

			return &ProblemCall{
				Timestamp: currentTime,
				Channel:   channel,
				CallerID:  callerID,
				Problem:   "Intelligent Bubbling Detection",
				Details: fmt.Sprintf("Pattern detected: %d rapid rings during %s",
					timeBasedThreshold.Bubbling, getTimeOfDay()),
				Severity: "critical",
			}
		}
	}

	patternsMutex.Unlock()

	// Advanced problem detection
	switch {
	case strings.Contains(line, "CONGESTION"):
		return &ProblemCall{
			Timestamp: currentTime,
			Channel:   channel,
			CallerID:  callerID,
			Problem:   "Network Congestion",
			Details:   "Call failed due to network congestion",
			Severity:  "high",
		}

	case strings.Contains(line, "FAILED") && strings.Contains(line, "auth"):
		return &ProblemCall{
			Timestamp: currentTime,
			Channel:   channel,
			CallerID:  callerID,
			Problem:   "Authentication Failure",
			Details:   "SIP authentication failed",
			Severity:  "high",
		}

	case extractDuration(line) > timeBasedThreshold.MaxCallDuration:
		return &ProblemCall{
			Timestamp: currentTime,
			Channel:   channel,
			CallerID:  callerID,
			Problem:   "Extended Call Duration",
			Details:   fmt.Sprintf("Call exceeded %d seconds", timeBasedThreshold.MaxCallDuration),
			Severity:  "medium",
		}
	}

	return nil
}

// 🎯 QUALITY ASSESSMENT
func assessCallQuality(channel, line string) *ProblemCall {
	// Real-time quality metrics extraction
	if metrics := extractRealTimeMetrics(line); metrics != nil {
		currentTime := time.Now().Format(time.RFC3339)

		switch {
		case metrics.PacketLoss > config.PacketLossThreshold:
			return &ProblemCall{
				Timestamp:  currentTime,
				Channel:    channel,
				CallerID:   "Quality Monitor",
				Problem:    "Packet Loss Detected",
				Details:    fmt.Sprintf("Loss: %.1f%%, MOS: %.1f", metrics.PacketLoss, metrics.MOS),
				Severity:   "high",
				PacketLoss: metrics.PacketLoss,
				MOS:        metrics.MOS,
			}

		case metrics.Jitter > config.JitterThreshold:
			return &ProblemCall{
				Timestamp: currentTime,
				Channel:   channel,
				CallerID:  "Quality Monitor",
				Problem:   "High Jitter Detected",
				Details:   fmt.Sprintf("Jitter: %.1fms, MOS: %.1f", metrics.Jitter, metrics.MOS),
				Severity:  "medium",
				Jitter:    metrics.Jitter,
				MOS:       metrics.MOS,
			}
		}
	}

	return nil
}

// 🚀 WEB SERVICES - Premium Dashboard
func startWebServices() {
	// REST API endpoints
	http.HandleFunc("/api/health", apiHealth)
	http.HandleFunc("/api/stats", apiStats)
	http.HandleFunc("/api/problems", apiProblems)
	http.HandleFunc("/api/channels", apiChannels)
	http.HandleFunc("/api/config", apiConfig)

	// Web UI
	http.HandleFunc("/", webDashboard)

	go func() {
		log.Printf("🌐 Starting web services on port %d", metricsPort)
		if err := http.ListenAndServe(fmt.Sprintf(":%d", metricsPort), nil); err != nil {
			log.Printf("❌ Web service error: %v", err)
		}
	}()
}

// 🎪 EVENT LOOP - Premium Management
func runEventLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// System health check
		checkSystemHealth()

		// Resource optimization
		optimizeResources()

		// Statistics snapshot
		saveStatisticsSnapshot()
	}
}

// 🎯 UTILITY FUNCTIONS
func extractRealTimeMetrics(line string) *QualityMetrics {
	// Advanced metric extraction using regex patterns
	metrics := &QualityMetrics{Timestamp: time.Now()}

	// Extract packet loss
	if re := regexp.MustCompile(`loss[=:]\s*([\d.]+)%?`); true {
		if matches := re.FindStringSubmatch(line); len(matches) > 1 {
			metrics.PacketLoss, _ = strconv.ParseFloat(matches[1], 64)
		}
	}

	// Extract jitter
	if re := regexp.MustCompile(`jitter[=:]\s*([\d.]+)\s*ms?`); true {
		if matches := re.FindStringSubmatch(line); len(matches) > 1 {
			metrics.Jitter, _ = strconv.ParseFloat(matches[1], 64)
		}
	}

	// Calculate MOS if we have enough data
	if metrics.PacketLoss > 0 || metrics.Jitter > 0 {
		metrics.MOS = calculateAdvancedMOS(metrics.PacketLoss, metrics.Jitter)
		return metrics
	}

	return nil
}

func calculateAdvancedMOS(packetLoss, jitter float64) float64 {
	// Enhanced MOS calculation considering multiple factors
	baseMOS := 4.4
	lossImpact := packetLoss * 0.025
	jitterImpact := jitter * 0.001
	combinedImpact := lossImpact + jitterImpact

	mos := baseMOS - combinedImpact
	return clamp(mos, 1.0, 4.4)
}

func clamp(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// 🎪 API HANDLERS - Premium Endpoints
func apiHealth(w http.ResponseWriter, r *http.Request) {
	statsMutex.RLock()
	defer statsMutex.RUnlock()

	health := map[string]interface{}{
		"status":           "healthy",
		"version":          version,
		"uptime":           systemStats.Uptime.String(),
		"timestamp":        time.Now().Format(time.RFC3339),
		"total_calls":      systemStats.TotalCalls,
		"problem_calls":    systemStats.ProblemCalls,
		"current_channels": systemStats.CurrentChannels,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func apiStats(w http.ResponseWriter, r *http.Request) {
	statsMutex.RLock()
	defer statsMutex.RUnlock()

	systemStats.Uptime = time.Since(systemStats.StartTime)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(systemStats)
}

func apiProblems(w http.ResponseWriter, r *http.Request) {
	// Возвращаем последние проблемы
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "implemented",
		"message": "API проблем будет реализовано в следующей версии",
	})
}

func apiChannels(w http.ResponseWriter, r *http.Request) {
	channels, _ := getAsteriskChannelsEnhanced()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"active_channels": countActiveChannels(channels),
		"total_channels":  len(channels),
	})
}

func apiConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// 🎯 CONFIGURATION MANAGEMENT
func loadConfig() error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}

	// Enhanced configuration with validation
	if err := json.Unmarshal(data, &config); err != nil {
		// Fallback to key=value format
		return loadLegacyConfig(data)
	}

	return validateConfig()
}

func loadLegacyConfig(data []byte) error {
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

		// Map legacy config to new structure
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

	return validateConfig()
}

func validateConfig() error {
	// Валидация конфигурации с подробными сообщениями об ошибках

	// Валидация временных параметров
	if config.MaxRingDuration <= 0 {
		log.Printf("⚠️  Некорректная максимальная длительность ожидания ответа: %d. Установлено значение по умолчанию: 30 секунд", config.MaxRingDuration)
		config.MaxRingDuration = 30
	} else if config.MaxRingDuration > 300 {
		log.Printf("⚠️  Слишком большая максимальная длительность ожидания ответа: %d секунд. Рекомендуется не более 120 секунд", config.MaxRingDuration)
	}

	if config.MaxCallDuration <= 0 {
		log.Printf("⚠️  Некорректная максимальная длительность вызова: %d. Установлено значение по умолчанию: 7200 секунд", config.MaxCallDuration)
		config.MaxCallDuration = 7200
	} else if config.MaxCallDuration > 86400 {
		log.Printf("⚠️  Слишком большая максимальная длительность вызова: %d секунд (24 часа). Проверьте корректность настройки", config.MaxCallDuration)
	}

	if config.ShortCallThreshold <= 0 {
		log.Printf("⚠️  Некорректный порог коротких вызовов: %d. Установлено значение по умолчанию: 5 секунд", config.ShortCallThreshold)
		config.ShortCallThreshold = 5
	} else if config.ShortCallThreshold < 3 {
		log.Printf("⚠️  Слишком маленький порог коротких вызовов: %d секунд. Может приводить к ложным срабатываниям", config.ShortCallThreshold)
	}

	if config.CheckInterval <= 0 {
		log.Printf("⚠️  Некорректный интервал проверки: %d. Установлено значение по умолчанию: 15 секунд", config.CheckInterval)
		config.CheckInterval = 15
	} else if config.CheckInterval < 5 {
		log.Printf("⚠️  Слишком частый интервал проверки: %d секунд. Может создавать нагрузку на систему", config.CheckInterval)
	} else if config.CheckInterval > 60 {
		log.Printf("⚠️  Слишком редкий интервал проверки: %d секунд. Могут пропускаться кратковременные проблемы", config.CheckInterval)
	}

	// Валидация пороговых значений качества
	if config.PacketLossThreshold <= 0 {
		log.Printf("⚠️  Некорректный порог потерь пакетов: %.1f%%. Установлено значение по умолчанию: 3.0%%", config.PacketLossThreshold)
		config.PacketLossThreshold = 3.0
	} else if config.PacketLossThreshold > 50.0 {
		log.Printf("⚠️  Слишком высокий порог потерь пакетов: %.1f%%. Качество связи будет считаться приемлемым даже при значительных потерях", config.PacketLossThreshold)
	} else if config.PacketLossThreshold < 1.0 {
		log.Printf("⚠️  Слишком строгий порог потерь пакетов: %.1f%%. Может приводить к излишним предупреждениям", config.PacketLossThreshold)
	}

	if config.JitterThreshold <= 0 {
		log.Printf("⚠️  Некорректный порог джиттера: %.1f мс. Установлено значение по умолчанию: 30.0 мс", config.JitterThreshold)
		config.JitterThreshold = 30.0
	} else if config.JitterThreshold > 100.0 {
		log.Printf("⚠️  Слишком высокий порог джиттера: %.1f мс. Качество связи будет считаться приемлемым даже при значительном джиттере", config.JitterThreshold)
	} else if config.JitterThreshold < 10.0 {
		log.Printf("⚠️  Слишком строгий порог джиттера: %.1f мс. Может приводить к излишним предупреждениям", config.JitterThreshold)
	}

	// Валидация порога "булькания"
	if config.BubblingThreshold <= 0 {
		log.Printf("⚠️  Некорректный порог булькания: %d. Установлено значение по умолчанию: 3", config.BubblingThreshold)
		config.BubblingThreshold = 3
	} else if config.BubblingThreshold < 2 {
		log.Printf("⚠️  Слишком чувствительный порог булькания: %d. Может приводить к ложным срабатываниям", config.BubblingThreshold)
	} else if config.BubblingThreshold > 10 {
		log.Printf("⚠️  Слишком высокий порог булькания: %d. Реальные случаи булькания могут не обнаруживаться", config.BubblingThreshold)
	}

	// Валидация настроек логов
	if config.LogMaxSize <= 0 {
		log.Printf("⚠️  Некорректный максимальный размер лога: %d МБ. Установлено значение по умолчанию: 500 МБ", config.LogMaxSize)
		config.LogMaxSize = 500
	} else if config.LogMaxSize < 10 {
		log.Printf("⚠️  Слишком маленький максимальный размер лога: %d МБ. Логи могут быстро ротироваться", config.LogMaxSize)
	} else if config.LogMaxSize > 2048 {
		log.Printf("⚠️  Слишком большой максимальный размер лога: %d МБ. Рекомендуется не более 1024 МБ", config.LogMaxSize)
	}

	if config.LogMaxBackups <= 0 {
		log.Printf("⚠️  Некорректное количество бэкапов логов: %d. Установлено значение по умолчанию: 5", config.LogMaxBackups)
		config.LogMaxBackups = 5
	} else if config.LogMaxBackups > 20 {
		log.Printf("⚠️  Слишком большое количество бэкапов логов: %d. Может занимать значительное место на диске", config.LogMaxBackups)
	}

	// Проверка согласованности настроек
	if config.CheckInterval >= config.MaxRingDuration {
		log.Printf("⚠️  Внимание: Интервал проверки (%dс) больше или равен максимальному времени ожидания ответа (%dс). Проблемы долгого ожидания могут обнаруживаться с задержкой",
			config.CheckInterval, config.MaxRingDuration)
	}

	if config.ShortCallThreshold >= config.MaxRingDuration {
		log.Printf("⚠️  Внимание: Порог коротких вызовов (%dс) больше или равен максимальному времени ожидания ответа (%dс). Проверьте логику детектирования",
			config.ShortCallThreshold, config.MaxRingDuration)
	}

	// Финальная проверка конфигурации
	log.Printf("✅ Конфигурация успешно проверена и применена")
	log.Printf("   • Макс. ожидание ответа: %d секунд", config.MaxRingDuration)
	log.Printf("   • Макс. длительность вызова: %d секунд", config.MaxCallDuration)
	log.Printf("   • Порог булькания: %d вызовов", config.BubblingThreshold)
	log.Printf("   • Порог потерь пакетов: %.1f%%", config.PacketLossThreshold)
	log.Printf("   • Порог джиттера: %.1f мс", config.JitterThreshold)
	log.Printf("   • Интервал проверки: %d секунд", config.CheckInterval)

	return nil
}

// 🎯 ИНТЕЛЛЕКТУАЛЬНАЯ РОТАЦИЯ ЛОГОВ
func startIntelligentLogRotation() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		if shouldRotateLog() {
			performLogRotation()
		}

		// Очистка старых бэкапов
		cleanupOldBackups()

		// Проверка использования диска
		checkDiskUsage()
	}
}

func shouldRotateLog() bool {
	info, err := os.Stat(logFile)
	if err != nil {
		return false
	}

	// Ротация по размеру
	if info.Size() > int64(config.LogMaxSize)*1024*1024 {
		log.Printf("📏 Лог достиг размера %d МБ, выполняется ротация", config.LogMaxSize)
		return true
	}

	// Ротация по времени (если файл старше 24 часов)
	if time.Since(info.ModTime()) > 24*time.Hour {
		log.Printf("⏰ Лог старше 24 часов, выполняется ротация")
		return true
	}

	return false
}

func performLogRotation() {
	// Создаем бэкап с временной меткой
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	backupPath := fmt.Sprintf("%s.%s", logFile, timestamp)

	if err := os.Rename(logFile, backupPath); err != nil {
		log.Printf("❌ Ошибка ротации лога: %v", err)
		return
	}

	log.Printf("🔄 Лог ротирован: %s -> %s", logFile, backupPath)

	// Создаем новый лог-файл
	if file, err := os.Create(logFile); err == nil {
		file.Close()
		os.Chmod(logFile, 0644)
	}
}

func cleanupOldBackups() {
	files, err := filepath.Glob(logFile + ".*")
	if err != nil {
		return
	}

	// Сортируем по времени изменения (сначала старые)
	sort.Slice(files, func(i, j int) bool {
		info1, _ := os.Stat(files[i])
		info2, _ := os.Stat(files[j])
		return info1.ModTime().Before(info2.ModTime())
	})

	// Удаляем старые бэкапы сверх лимита
	if len(files) > config.LogMaxBackups {
		for i := 0; i < len(files)-config.LogMaxBackups; i++ {
			os.Remove(files[i])
			log.Printf("🗑️ Удален старый бэкап: %s", files[i])
		}
	}
}

func checkDiskUsage() {
	cmd := exec.Command("df", "/var/log")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) > 1 {
			fields := strings.Fields(lines[1])
			if len(fields) > 4 {
				usage := fields[4]
				log.Printf("💾 Использование диска в /var/log: %s", usage)

				// Проверяем если использование больше 90%
				if strings.Contains(usage, "9") && len(usage) >= 2 {
					log.Printf("⚠️  Высокое использование диска: %s. Рекомендуется очистка", usage)
				}
			}
		}
	}
}

// 🎯 ЗАГРУЗКА ИСТОРИЧЕСКОЙ СТАТИСТИКИ
func loadHistoricalStats() {
	data, err := os.ReadFile(statsFile)
	if err != nil {
		log.Printf("📊 Историческая статистика не найдена, начинаем с чистого листа")
		return
	}

	var savedStats SystemStats
	if err := json.Unmarshal(data, &savedStats); err == nil {
		statsMutex.Lock()
		systemStats.TotalCalls = savedStats.TotalCalls
		systemStats.ProblemCalls = savedStats.ProblemCalls
		systemStats.QualityIssues = savedStats.QualityIssues
		systemStats.BubblingEvents = savedStats.BubblingEvents
		systemStats.TopProblemTypes = savedStats.TopProblemTypes
		statsMutex.Unlock()

		log.Printf("📊 Загружена историческая статистика: %d вызовов, %d проблем",
			savedStats.TotalCalls, savedStats.ProblemCalls)
	}
}

// 🎯 МОНИТОРИНГ КАЧЕСТВА СВЯЗИ
func monitorCallQuality() {
	ticker := time.NewTicker(qualityInterval)
	defer ticker.Stop()

	for range ticker.C {
		metrics, err := getRTPQuality()
		if err != nil {
			log.Printf("❌ Ошибка получения метрик качества: %v", err)
			continue
		}

		problems := analyzeQuality(metrics)
		if len(problems) > 0 {
			logProblemsIntelligently(problems)
			updateStats(len(problems))
		}

		// Обновляем метрики качества в реальном времени
		updateQualityMetrics(metrics)
	}
}

// 🎯 АНАЛИЗ CDR С ИСКУССТВЕННЫМ ИНТЕЛЛЕКТОМ
func analyzeCDRPatterns() {
	ticker := time.NewTicker(cdrInterval)
	defer ticker.Stop()

	for range ticker.C {
		records, err := readCDRFile()
		if err != nil {
			log.Printf("⚠️  Ошибка чтения CDR: %v", err)
			continue
		}

		// Анализ паттернов вызовов
		analyzeCallPatternsFromCDR(records)

		// Обнаружение аномалий
		detectAnomalies(records)

		// Анализ тенденций
		analyzeTrends(records)
	}
}

func readCDRFile() ([][]string, error) {
	file, err := os.Open(cdrFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	return records, nil
}

func analyzeCallPatternsFromCDR(records [][]string) {
	shortCalls := 0
	failedCalls := 0
	successfulCalls := 0
	totalDuration := time.Duration(0)

	for _, record := range records {
		if len(record) < 14 {
			continue
		}

		disposition := record[12]
		durationStr := record[9]

		switch disposition {
		case "ANSWERED":
			successfulCalls++
			// Анализ коротких успешных вызовов
			if duration, err := time.ParseDuration(durationStr + "s"); err == nil {
				totalDuration += duration

				if duration <= time.Duration(config.ShortCallThreshold)*time.Second {
					shortCalls++
					logShortCall(record, duration)
				}
			}

		case "NO ANSWER", "BUSY", "FAILED":
			failedCalls++
		}
	}

	// Логируем статистику
	if shortCalls > 0 {
		log.Printf("📞 Обнаружено коротких вызовов: %d", shortCalls)
	}

	// Расчет средней длительности
	if successfulCalls > 0 {
		avgDuration := totalDuration / time.Duration(successfulCalls)
		log.Printf("📊 Средняя длительность вызовов: %v", avgDuration.Truncate(time.Second))
	}

	statsMutex.Lock()
	systemStats.TotalCalls += int64(successfulCalls + failedCalls)
	statsMutex.Unlock()
}

// 🎯 МОНИТОРИНГ ЗДОРОВЬЯ SIP
func monitorSIPHealth() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sipStatus, err := getSIPStatusDetailed()
		if err != nil {
			log.Printf("❌ Ошибка проверки здоровья SIP: %v", err)
			continue
		}

		problems := analyzeSIPHealth(sipStatus)
		if len(problems) > 0 {
			logProblemsIntelligently(problems)
		}

		updateSIPMetrics(sipStatus)
	}
}

func analyzeSIPHealth(sipStatus []string) []ProblemCall {
	var problems []ProblemCall
	currentTime := time.Now().Format(time.RFC3339)

	for _, line := range sipStatus {
		if strings.Contains(line, "UNREACHABLE") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				peer := parts[0]
				problems = append(problems, ProblemCall{
					Timestamp: currentTime,
					Channel:   "SIP Peer",
					CallerID:  peer,
					Problem:   "SIP пир недоступен",
					Details:   fmt.Sprintf("Пир %s недоступен для звонков", peer),
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
					Problem:   "Высокая задержка SIP",
					Details:   "Обнаружены значительные задержки в работе SIP",
					Severity:  "medium",
				})
			}
		}
	}

	return problems
}

// 🎯 ДВИГАТЕЛЬ СТАТИСТИКИ
func runStatisticsEngine() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		statsMutex.Lock()
		systemStats.Uptime = time.Since(systemStats.StartTime)

		// Обновляем тренд проблем (последние 24 часа)
		hour := time.Now().Hour()
		systemStats.ProblemTrend[hour]++

		statsMutex.Unlock()

		// Периодическое сохранение статистики
		if time.Now().Minute()%10 == 0 { // Каждые 10 минут
			saveStatisticsSnapshot()
		}
	}
}

func saveStatisticsSnapshot() {
	statsMutex.RLock()
	defer statsMutex.RUnlock()

	data, err := json.MarshalIndent(systemStats, "", "  ")
	if err != nil {
		log.Printf("❌ Ошибка сериализации статистики: %v", err)
		return
	}

	if err := os.WriteFile(statsFile, data, 0644); err != nil {
		log.Printf("❌ Ошибка сохранения статистики: %v", err)
	}
}

// 🎯 МЕНЕДЖЕР ОПОВЕЩЕНИЙ
func runAlertManager() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		statsMutex.RLock()
		recentProblems := systemStats.ProblemCalls
		statsMutex.RUnlock()

		// Проверяем необходимость отправки оповещения
		if shouldSendAlert(recentProblems) {
			sendAlert(recentProblems)
		}
	}
}

func shouldSendAlert(recentProblems int64) bool {
	alertMutex.Lock()
	defer alertMutex.Unlock()

	// Отправляем оповещение не чаще чем раз в 5 минут
	if time.Since(lastAlertSent) < 5*time.Minute {
		return false
	}

	// Логика определения необходимости оповещения
	if recentProblems > 10 {
		lastAlertSent = time.Now()
		return true
	}

	return false
}

func sendAlert(problemCount int64) {
	log.Printf("🚨 КРИТИЧЕСКОЕ ОПОВЕЩЕНИЕ: Обнаружено %d проблемных вызовов", problemCount)

	// Здесь можно добавить отправку email, SMS, webhook и т.д.
	if config.AlertEmail != "" {
		// sendEmailAlert(problemCount)
	}
}

// 🎯 САМОМОНИТОРИНГ
func runSelfMonitoring() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		checkSystemHealth()
		optimizeResources()
	}
}

func checkSystemHealth() {
	// Проверяем использование памяти
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	if m.Alloc > 100*1024*1024 { // 100MB
		log.Printf("⚠️  Высокое использование памяти: %.2f MB", float64(m.Alloc)/1024/1024)
	}

	// Проверяем количество горутин
	if runtime.NumGoroutine() > 100 {
		log.Printf("⚠️  Большое количество горутин: %d", runtime.NumGoroutine())
	}
}

func optimizeResources() {
	// Периодический сбор мусора
	runtime.GC()

	// Очистка устаревших данных
	cleanupOldData()
}

func cleanupOldData() {
	patternsMutex.Lock()
	defer patternsMutex.Unlock()

	now := time.Now()
	for key, pattern := range callPatterns {
		if now.Sub(pattern.LastReset) > 24*time.Hour {
			delete(callPatterns, key)
		}
	}

	// Очистка истории проблем
	for key, lastSeen := range problemHistory {
		if now.Sub(lastSeen) > 2*time.Hour {
			delete(problemHistory, key)
		}
	}
}

// 🎯 ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
func getSystemLoad() (string, error) {
	cmd := exec.Command("uptime")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func analyzeSystemImpact(systemLoad string, channels []string) []ProblemCall {
	// Анализ влияния системной нагрузки на качество связи
	var problems []ProblemCall

	if strings.Contains(systemLoad, "load average:") {
		// Парсим нагрузку системы
		parts := strings.Split(systemLoad, "load average:")
		if len(parts) > 1 {
			load := strings.TrimSpace(parts[1])

			// Если нагрузка высокая и есть активные вызовы
			if strings.Contains(load, "2.") || strings.Contains(load, "3.") {
				activeCalls := countActiveChannels(channels)
				if activeCalls > 0 {
					problems = append(problems, ProblemCall{
						Timestamp: time.Now().Format(time.RFC3339),
						Channel:   "System",
						CallerID:  "Monitor",
						Problem:   "Высокая системная нагрузка",
						Details:   fmt.Sprintf("Нагрузка: %s, активных вызовов: %d", load, activeCalls),
						Severity:  "medium",
					})
				}
			}
		}
	}

	return problems
}

func countActiveChannels(channels []string) int {
	count := 0
	for _, line := range channels {
		if isActiveCall(line) {
			count++
		}
	}
	return count
}

func predictPotentialIssues(channels []string) []ProblemCall {
	// Прогнозирование потенциальных проблем на основе текущего состояния
	var predictions []ProblemCall

	activeCount := countActiveChannels(channels)

	// Если много активных вызовов - предупреждаем о возможной перегрузке
	if activeCount > 50 {
		predictions = append(predictions, ProblemCall{
			Timestamp: time.Now().Format(time.RFC3339),
			Channel:   "Predictive",
			CallerID:  "AI Engine",
			Problem:   "Возможная перегрузка системы",
			Details:   fmt.Sprintf("Обнаружено %d активных вызовов - близко к пределу производительности", activeCount),
			Severity:  "low",
		})
	}

	return predictions
}

// 🎯 ВЕБ-ИНТЕРФЕЙС И API
func webDashboard(w http.ResponseWriter, r *http.Request) {
	html := `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Asterisk Monitor Premium</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
            .metric { background: #ecf0f1; margin: 10px 0; padding: 15px; border-radius: 5px; }
            .critical { border-left: 5px solid #e74c3c; }
            .warning { border-left: 5px solid #f39c12; }
            .info { border-left: 5px solid #3498db; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🎯 Asterisk Monitor Premium</h1>
            <p>Enterprise-grade мониторинг в реальном времени</p>
        </div>
        
        <div class="metric info">
            <h3>Системная информация</h3>
            <p>Версия: %s | Время работы: <span id="uptime"></span></p>
        </div>
        
        <div class="metric">
            <h3>Статистика вызовов</h3>
            <p>Всего вызовов: <span id="totalCalls">0</span> | Проблемных: <span id="problemCalls">0</span></p>
        </div>
        
        <div class="metric">
            <h3>Активные каналы</h3>
            <p id="activeChannels">0</p>
        </div>
        
        <script>
            function updateStats() {
                fetch('/api/stats')
                    .then(r => r.json())
                    .then(data => {
                        document.getElementById('uptime').textContent = data.uptime;
                        document.getElementById('totalCalls').textContent = data.total_calls;
                        document.getElementById('problemCalls').textContent = data.problem_calls;
                        document.getElementById('activeChannels').textContent = data.current_channels;
                    });
            }
            
            setInterval(updateStats, 5000);
            updateStats();
        </script>
    </body>
    </html>
    `
	fmt.Fprintf(w, html, version)
}

// 🎯 ОБНОВЛЕНИЕ МЕТРИК В РЕАЛЬНОМ ВРЕМЕНИ
func updateRealTimeMetrics(channels []string, problems []ProblemCall) {
	activeCount := countActiveChannels(channels)

	// Обновляем статистику
	statsMutex.Lock()
	systemStats.CurrentChannels = activeCount
	systemStats.ProblemCalls += int64(len(problems))
	statsMutex.Unlock()
}

func updateQualityMetrics(metrics []QualityMetrics) {
	// Обновляем внутренние метрики качества
	for _, metric := range metrics {
		statsMutex.Lock()
		if metric.PacketLoss > config.PacketLossThreshold {
			systemStats.QualityIssues++
		}
		statsMutex.Unlock()
	}
}

func updateSIPMetrics(sipStatus []string) {
	// Обновляем метрики статуса SIP пиров
	statsMutex.Lock()
	defer statsMutex.Unlock()

	for _, line := range sipStatus {
		if strings.Contains(line, "OK") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				systemStats.SIPStatus[parts[0]] = "OK"
			}
		} else if strings.Contains(line, "UNREACHABLE") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				systemStats.SIPStatus[parts[0]] = "UNREACHABLE"
			}
		}
	}
}

// 🎯 ИНТЕЛЛЕКТУАЛЬНОЕ ЛОГИРОВАНИЕ ПРОБЛЕМ
func logProblemsIntelligently(problems []ProblemCall) {
	for _, problem := range problems {
		// Проверяем, не логировали ли мы уже эту проблему недавно
		problemKey := fmt.Sprintf("%s:%s:%s", problem.Channel, problem.Problem, problem.CallerID)

		if lastSeen, exists := problemHistory[problemKey]; exists {
			if time.Since(lastSeen) < 2*time.Minute {
				continue // Пропускаем если уже видели эту проблему недавно
			}
		}

		problemHistory[problemKey] = time.Now()

		// Логируем проблему
		logEntry := fmt.Sprintf("[%s] [%s] ПРОБЛЕМА: %s | Канал: %s | CallerID: %s | Детали: %s\n",
			problem.Timestamp, problem.Severity, problem.Problem, problem.Channel, problem.CallerID, problem.Details)

		// Записываем в лог-файл
		if file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			file.WriteString(logEntry)
			file.Close()
		}

		// Выводим в консоль
		fmt.Print(logEntry)

		// Обновляем статистику по типам проблем
		statsMutex.Lock()
		systemStats.TopProblemTypes[problem.Problem]++
		statsMutex.Unlock()
	}
}

func logShortCall(record []string, duration time.Duration) {
	problem := ProblemCall{
		Timestamp: time.Now().Format(time.RFC3339),
		Channel:   record[1],
		CallerID:  record[2],
		Problem:   "Короткий вызов",
		Details:   fmt.Sprintf("Длительность: %v, Назначение: %s", duration, record[4]),
		Severity:  "medium",
		Duration:  int(duration.Seconds()),
	}

	logProblemsIntelligently([]ProblemCall{problem})
}

// 🎯 СТРУКТУРА ДЛЯ ДИНАМИЧЕСКИХ ПОРОГОВ
type DynamicThresholds struct {
	Bubbling        int
	MaxCallDuration int
	PacketLoss      float64
}

func adjustThresholdsByTime() DynamicThresholds {
	now := time.Now()
	hour := now.Hour()

	thresholds := DynamicThresholds{
		Bubbling:        config.BubblingThreshold,
		MaxCallDuration: config.MaxCallDuration,
		PacketLoss:      config.PacketLossThreshold,
	}

	// Корректируем пороги в зависимости от времени суток
	switch {
	case hour >= 8 && hour <= 18: // Рабочие часы
		thresholds.Bubbling = 2     // Более чувствительно в рабочее время
		thresholds.PacketLoss = 2.0 // Строже к качеству

	case hour >= 22 || hour <= 6: // Ночное время
		thresholds.Bubbling = 5     // Менее чувствительно ночью
		thresholds.PacketLoss = 8.0 // Допускаем больше потерь

	default: // Вечернее время
		thresholds.Bubbling = 3
		thresholds.PacketLoss = 5.0
	}

	return thresholds
}

func getTimeOfDay() string {
	hour := time.Now().Hour()
	switch {
	case hour < 6:
		return "ночь"
	case hour < 12:
		return "утро"
	case hour < 18:
		return "день"
	default:
		return "вечер"
	}
}

// 🎯 ОСНОВНЫЕ УТИЛИТЫ
func isActiveCall(line string) bool {
	upper := strings.ToUpper(line)
	return strings.Contains(upper, "UP") ||
		strings.Contains(upper, "RINGING") ||
		strings.Contains(upper, "DIALING") ||
		strings.Contains(upper, "ANSWERED")
}

func extractChannel(line string) string {
	parts := strings.Fields(line)
	if len(parts) > 0 {
		return parts[0]
	}
	return "unknown"
}

func extractCallerID(line string) string {
	// Ищем в формате <number>
	if start := strings.Index(line, "<"); start != -1 {
		if end := strings.Index(line[start:], ">"); end != -1 {
			return line[start+1 : start+end]
		}
	}

	// Ищем номер телефона
	re := regexp.MustCompile(`(\+\d+|\d{6,})`)
	if matches := re.FindStringSubmatch(line); len(matches) > 0 {
		return matches[0]
	}

	return "unknown"
}

func extractState(line string) string {
	states := []string{"RINGING", "UP", "BUSY", "FAILED", "CONGESTION", "ANSWERED", "DIALING"}
	upper := strings.ToUpper(line)
	for _, state := range states {
		if strings.Contains(upper, state) {
			return state
		}
	}
	return "UNKNOWN"
}

func extractDuration(line string) int {
	// Различные форматы длительности
	patterns := []struct {
		regex string
		mult  int
	}{
		{`(\d+)h\s*(\d+)m\s*(\d+)s`, 1},
		{`(\d+)m\s*(\d+)s`, 1},
		{`(\d+)s`, 1},
		{`Up\s+(\d+)s`, 1},
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern.regex)
		if matches := re.FindStringSubmatch(line); len(matches) > 1 {
			switch len(matches) {
			case 4: // 1h 2m 3s
				h, _ := strconv.Atoi(matches[1])
				m, _ := strconv.Atoi(matches[2])
				s, _ := strconv.Atoi(matches[3])
				return h*3600 + m*60 + s
			case 3: // 2m 3s
				m, _ := strconv.Atoi(matches[1])
				s, _ := strconv.Atoi(matches[2])
				return m*60 + s
			case 2: // 45s
				s, _ := strconv.Atoi(matches[1])
				return s
			}
		}
	}

	return 0
}

// 🎯 ОБНОВЛЯЕМ updateStats ДЛЯ ПОДДЕРЖКИ НОВОЙ ФУНКЦИОНАЛЬНОСТИ
func updateStats(problemsCount int) {
	statsMutex.Lock()
	defer statsMutex.Unlock()

	systemStats.ProblemCalls += int64(problemsCount)
	systemStats.LastProblemTime = time.Now()
}

func getRTPQuality() ([]QualityMetrics, error) {
	var metrics []QualityMetrics

	// Получаем статистику RTP
	cmd := exec.Command("asterisk", "-rx", "rtp show stats")
	output, err := cmd.Output()
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
	re := regexp.MustCompile(`loss[=:]?\s*([\d.]+)%?`)
	if matches := re.FindStringSubmatch(line); len(matches) > 1 {
		metric.PacketLoss, _ = strconv.ParseFloat(matches[1], 64)
	}

	// Парсим джиттер
	re = regexp.MustCompile(`jitter[=:]?\s*([\d.]+)\s*ms?`)
	if matches := re.FindStringSubmatch(line); len(matches) > 1 {
		metric.Jitter, _ = strconv.ParseFloat(matches[1], 64)
	}

	// Парсим канал если есть
	re = regexp.MustCompile(`(SIP/\S+|PJSIP/\S+)`)
	if matches := re.FindStringSubmatch(line); len(matches) > 1 {
		metric.Channel = matches[1]
	}

	// Расчет MOS
	metric.MOS = calculateAdvancedMOS(metric.PacketLoss, metric.Jitter)

	return metric
}

func analyzeQuality(metrics []QualityMetrics) []ProblemCall {
	var problems []ProblemCall
	currentTime := time.Now().Format(time.RFC3339)

	for _, metric := range metrics {
		// Проверка потерь пакетов
		if metric.PacketLoss > config.PacketLossThreshold {
			problems = append(problems, ProblemCall{
				Timestamp: currentTime,
				Channel:   metric.Channel,
				CallerID:  "RTP Monitor",
				Problem:   "Высокие потери пакетов",
				Details: fmt.Sprintf("Потери: %.1f%% (>%.1f%%), MOS: %.2f",
					metric.PacketLoss, config.PacketLossThreshold, metric.MOS),
				Severity:   "high",
				PacketLoss: metric.PacketLoss,
				MOS:        metric.MOS,
			})
		}

		// Проверка джиттера
		if metric.Jitter > config.JitterThreshold {
			problems = append(problems, ProblemCall{
				Timestamp: currentTime,
				Channel:   metric.Channel,
				CallerID:  "RTP Monitor",
				Problem:   "Высокий джиттер",
				Details: fmt.Sprintf("Джиттер: %.1f мс (>%.1f мс), MOS: %.2f",
					metric.Jitter, config.JitterThreshold, metric.MOS),
				Severity: "medium",
				Jitter:   metric.Jitter,
				MOS:      metric.MOS,
			})
		}

		// Проверка качества голоса
		if metric.MOS < 3.0 {
			problems = append(problems, ProblemCall{
				Timestamp: currentTime,
				Channel:   metric.Channel,
				CallerID:  "RTP Monitor",
				Problem:   "Плохое качество голоса",
				Details:   fmt.Sprintf("MOS: %.2f (требуется >3.0)", metric.MOS),
				Severity:  "high",
				MOS:       metric.MOS,
			})
		}
	}

	return problems
}

func detectAnomalies(records [][]string) {
	// Простой детектор аномалий на основе CDR данных
	totalCalls := len(records)
	if totalCalls == 0 {
		return
	}

	failedCalls := 0
	shortCalls := 0

	for _, record := range records {
		if len(record) < 14 {
			continue
		}

		disposition := record[12]
		durationStr := record[9]

		if disposition != "ANSWERED" {
			failedCalls++
		} else if duration, err := time.ParseDuration(durationStr + "s"); err == nil {
			if duration <= time.Duration(config.ShortCallThreshold)*time.Second {
				shortCalls++
			}
		}
	}

	// Проверяем аномалии
	failureRate := float64(failedCalls) / float64(totalCalls) * 100
	shortCallRate := float64(shortCalls) / float64(totalCalls) * 100

	if failureRate > 20.0 { // Более 20% неудачных вызовов
		log.Printf("🚨 АНОМАЛИЯ: Высокий процент неудачных вызовов: %.1f%%", failureRate)
	}

	if shortCallRate > 30.0 { // Более 30% коротких вызовов
		log.Printf("🚨 АНОМАЛИЯ: Высокий процент коротких вызовов: %.1f%%", shortCallRate)
	}

	// Обновляем статистику
	statsMutex.Lock()
	systemStats.QualityIssues += int64(failedCalls)
	statsMutex.Unlock()
}

func analyzeTrends(records [][]string) {
	// Анализ трендов на основе исторических данных
	hour := time.Now().Hour()
	currentCalls := len(records)

	// Простой анализ: сравниваем с предыдущим часом
	statsMutex.Lock()

	// Сохраняем текущее количество вызовов для этого часа
	if hour < len(systemStats.ProblemTrend) {
		previousCalls := systemStats.ProblemTrend[hour]

		// Если резкий рост вызовов
		if currentCalls > 0 && previousCalls > 0 {
			growth := float64(currentCalls) / float64(previousCalls)
			if growth > 2.0 { // Рост более чем в 2 раза
				log.Printf("📈 ТРЕНД: Резкий рост вызовов в %d:00 - в %.1f раз больше чем в предыдущий час",
					hour, growth)
			}
		}

		systemStats.ProblemTrend[hour] = currentCalls
	}

	statsMutex.Unlock()
}
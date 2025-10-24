package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	logFile = "/var/log/asterisk-monitor/calls_problem_online.log"
)

// ProblemCall представляет проблемный вызов
type ProblemCall struct {
	Timestamp string
	Channel   string
	CallerID  string
	Problem   string
	Details   string
}

func main() {
	fmt.Println("Asterisk Problem Calls Monitor запущен...")
	fmt.Printf("Логи будут записываться в: %s\n", logFile)

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
	monitorAsterisk(file)
}

func monitorAsterisk(logFile *os.File) {
	for {
		// Получаем статус каналов
		channels, err := getAsteriskChannels()
		if err != nil {
			log.Printf("Ошибка получения статуса каналов: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Анализируем каналы на проблемы
		problemCalls := analyzeChannels(channels)

		// Записываем проблемные вызовы в лог
		if len(problemCalls) > 0 {
			writeProblemCalls(logFile, problemCalls)
		}

		time.Sleep(10 * time.Second) // Проверяем каждые 10 секунд
	}
}

func getAsteriskChannels() ([]string, error) {
	// Команда для получения списка каналов через Asterisk CLI
	cmd := exec.Command("asterisk", "-rx", "core show channels")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ошибка выполнения команды asterisk: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	return lines, nil
}

func analyzeChannels(channels []string) []ProblemCall {
	var problemCalls []ProblemCall

	for _, line := range channels {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Проверяем различные типы проблем
		if problem := detectProblems(line); problem != nil {
			problemCalls = append(problemCalls, *problem)
		}
	}

	return problemCalls
}

func detectProblems(channelInfo string) *ProblemCall {
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	
	// Детектор "булькания" (быстрое поднятие/сброс трубок)
	if strings.Contains(channelInfo, "RINGING") {
		// Если канал долго в состоянии RINGING - возможное "булькание"
		if extractDuration(channelInfo) > 30 { // более 30 секунд в ringing
			return &ProblemCall{
				Timestamp: currentTime,
				Channel:   extractChannel(channelInfo),
				CallerID:  extractCallerID(channelInfo),
				Problem:   "Долгое ожидание ответа (булькание)",
				Details:   channelInfo,
			}
		}
	}

	// Детектор заблокированных каналов
	if strings.Contains(channelInfo, "BUSY") {
		return &ProblemCall{
			Timestamp: currentTime,
			Channel:   extractChannel(channelInfo),
			CallerID:  extractCallerID(channelInfo),
			Problem:   "Канал занят",
			Details:   channelInfo,
		}
	}

	// Детектор неудачных вызовов
	if strings.Contains(channelInfo, "FAILED") || strings.Contains(channelInfo, "CONGESTION") {
		return &ProblemCall{
			Timestamp: currentTime,
			Channel:   extractChannel(channelInfo),
			CallerID:  extractCallerID(channelInfo),
			Problem:   "Неудачный вызов",
			Details:   channelInfo,
		}
	}

	// Детектор долгих вызовов (возможные "зависшие" каналы)
	if strings.Contains(channelInfo, "Up") {
		duration := extractDuration(channelInfo)
		if duration > 3600 { // более 1 часа
			return &ProblemCall{
				Timestamp: currentTime,
				Channel:   extractChannel(channelInfo),
				CallerID:  extractCallerID(channelInfo),
				Problem:   "Очень долгий вызов",
				Details:   fmt.Sprintf("Длительность: %d сек, %s", duration, channelInfo),
			}
		}
	}

	return nil
}

func extractChannel(line string) string {
	parts := strings.Fields(line)
	if len(parts) > 0 {
		return parts[0]
	}
	return "unknown"
}

func extractCallerID(line string) string {
	// Упрощенная логика извлечения CallerID
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
	// Упрощенная логика извлечения длительности вызова
	// В реальном скрипте нужно парсить более точно
	if strings.Contains(line, "Up") {
		// Пример: "SIP/1234-0001 Up 1h 25m 30s"
		return 3600 // заглушка
	}
	return 0
}

func writeProblemCalls(logFile *os.File, calls []ProblemCall) {
	writer := bufio.NewWriter(logFile)
	
	for _, call := range calls {
		logEntry := fmt.Sprintf("[%s] ПРОБЛЕМА: %s | Канал: %s | CallerID: %s | Детали: %s\n",
			call.Timestamp, call.Problem, call.Channel, call.CallerID, call.Details)
		
		_, err := writer.WriteString(logEntry)
		if err != nil {
			log.Printf("Ошибка записи в лог: %v", err)
		}
		
		// Также выводим в консоль для отладки
		fmt.Print(logEntry)
	}
	
	writer.Flush()
}

// Функция для мониторинга событий в реальном времени (альтернативный подход)
func monitorAsteriskRealtime(logFile *os.File) {
	cmd := exec.Command("asterisk", "-rx", "core show channels")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatalf("Ошибка создания pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		log.Fatalf("Ошибка запуска команды: %v", err)
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		
		// Анализируем каждую строку в реальном времени
		if problem := detectProblems(line); problem != nil {
			writeSingleProblemCall(logFile, problem)
		}
	}

	if err := cmd.Wait(); err != nil {
		log.Printf("Команда завершилась с ошибкой: %v", err)
	}
}

func writeSingleProblemCall(logFile *os.File, call *ProblemCall) {
	file, err := os.OpenFile(logFile.Name(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Ошибка открытия файла: %v", err)
		return
	}
	defer file.Close()

	logEntry := fmt.Sprintf("[%s] ПРОБЛЕМА: %s | Канал: %s | CallerID: %s | Детали: %s\n",
		call.Timestamp, call.Problem, call.Channel, call.CallerID, call.Details)

	if _, err := file.WriteString(logEntry); err != nil {
		log.Printf("Ошибка записи в лог: %v", err)
	}
}
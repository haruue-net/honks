package main

import (
	"fmt"
	"log"
	"strconv"
)

type LogLevel int

const (
	logLevelVerbose LogLevel = 0
	logLevelInfo    LogLevel = 1
	logLevelError   LogLevel = 5
	logLevelFatal   LogLevel = 7
)

func (l *LogLevel) UnmarshalJSON(bytes []byte) (err error) {
	if len(bytes) == 0 {
		*l = logLevelVerbose
		return
	}
	s, err := strconv.Unquote(string(bytes))
	if err != nil {
		return
	}
	if len(s) == 0 {
		*l = logLevelVerbose
		return
	}

	switch s {
	case "verbose":
		*l = logLevelVerbose
	case "info":
		*l = logLevelInfo
	case "error":
		*l = logLevelError
	case "fatal":
		*l = logLevelFatal
	default:
		err = fmt.Errorf("invalid log level: %s", s)
	}

	return
}

func logVerbose(fmt string, args ...interface{}) {
	if config.LogLevel <= logLevelVerbose {
		log.Printf("[verbose] "+fmt, args...)
	}
}

func logInfo(fmt string, args ...interface{}) {
	if config.LogLevel <= logLevelInfo {
		log.Printf("[info] "+fmt, args...)
	}
}

func logError(fmt string, args ...interface{}) {
	if config.LogLevel <= logLevelError {
		log.Printf("[error] "+fmt, args...)
	}
}

func logFatal(fmt string, args ...interface{}) {
	if config.LogLevel <= logLevelFatal {
		log.Fatalf("[fatal] "+fmt, args...)
	}
}

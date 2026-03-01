package mlog

import (
	"fmt"
	"log"
	"os"
)

type LogConfig struct {
	Level      string
	File       string
	Production bool
}

type Logger struct {
	debug  bool
	logger *log.Logger
}

func NewLogger(lc LogConfig) (*Logger, error) {
	out := os.Stderr
	if lc.File != "" {
		f, err := os.OpenFile(lc.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		out = f
	}

	flags := log.Ldate | log.Ltime
	l := log.New(out, "", flags)

	isDebug := false
	if lc.Level == "debug" {
		isDebug = true
	}

	return &Logger{
		debug:  isDebug,
		logger: l,
	}, nil
}

func (l *Logger) IsDebug() bool {
	return l.debug
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	if l.debug {
		l.logger.Printf(format, args...)
	}
}

func (l *Logger) Infof(format string, args ...interface{}) {
	l.logger.Printf(format, args...)
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	l.logger.Printf("Warn: "+format, args...)
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	l.logger.Printf("Error: "+format, args...)
}

// Below are stubs/helpers for transition or simple usage without formatting
func (l *Logger) Debug(msg string) { l.Debugf("%s", msg) }
func (l *Logger) Info(msg string)  { l.Infof("%s", msg) }
func (l *Logger) Warn(msg string)  { l.Warnf("%s", msg) }
func (l *Logger) Error(msg string) { l.Errorf("%s", msg) }

func (l *Logger) Fatal(msg string) {
	l.Errorf("%s", msg)
	os.Exit(1)
}

// With returns the same logger, kept for signature compatibility during transition
func (l *Logger) With(args ...interface{}) *Logger {
	return l
}

func Nop() *Logger {
	return &Logger{debug: false, logger: log.New(os.Stderr, "", 0)}
}

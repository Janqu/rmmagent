package main

import "testing"

func TestSetupLoggingStdoutDoesNotOpenLogFile(t *testing.T) {
	level := "INFO"
	to := "stdout"
	logFile = nil

	setupLogging(&level, &to)

	if logFile != nil {
		t.Fatal("stdout logging should not create a log file")
	}
}

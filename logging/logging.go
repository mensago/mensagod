package logging

import (
	"fmt"
	"log"
	"os"
)

var logHandle *os.File
var alsoStdout bool
var serverLog *log.Logger

// Init initializes the server logging facilities, including the possibility of printing all log
// messages to stdout
func Init(path string, includeStdout bool) {
	alsoStdout = includeStdout

	logHandle, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Unable to open log file %s. Aborting.\n", path)
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}
	serverLog = log.New(logHandle, "mensagod:", log.LstdFlags)
}

// GetLog returns a pointer to the global logging facilities
func GetLog() *log.Logger {
	return serverLog
}

// Shutdown shuts down the global logging facilities
func Shutdown() {
	logHandle.Close()
}

// Write prints a message to the log and stdout if turned on
func Write(msg string) {
	serverLog.Println(msg)
	if alsoStdout {
		fmt.Println(msg)
	}
}

// Writef is a Printf() interface to the log and possibly stdout
func Writef(msg string, v ...interface{}) {
	serverLog.Printf(msg, v...)
	if alsoStdout {
		fmt.Printf(msg, v...)
	}
}

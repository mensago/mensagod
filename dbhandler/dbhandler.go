package dbhandler

// This module is for abstracting away all the messy details of interacting with the database.
// By doing so, it will be easier to add support for databases other than Postgresql. It will also
// eliminate cluttering up the otherwise-clean Go code with the ugly SQL queries.

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/viper"
)

var connected bool
var serverLog *log.Logger

// Connect utilizes the viper config system and connects to the specified database. Because
// problems in the connection are almost always fatal to the successful continuation of the server
// daemon, if there are problems, it logs the problem and exits the main process.
func Connect(logHandle *log.Logger) {
	serverLog = logHandle
	if viper.GetString("database.engine") != "postgresql" {
		logHandle.Println("Database password not set in config file. Exiting.")
		fmt.Println("Database password not set in config file. Exiting.")
		os.Exit(1)
	}
}

// IsConnected returns a boolean if it has successfully connected to the Anselus server database
func IsConnected() bool {
	return connected
}

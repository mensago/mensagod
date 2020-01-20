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

// WorkspaceStatus indicates the activity status of a workspace.
type WorkspaceStatus int

const (
	// Active is the regular state of a workspace in use
	Active WorkspaceStatus = iota
	// Disabled workspaces cannot be logged into
	Disabled
	// Awaiting indicates the workspace is awaiting administrator approval
	Awaiting
)

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

// GetWorkspace checks to see if a workspace exists
func GetWorkspace(wid string) (WorkspaceStatus, bool) {

	// TODO: Implement
	return Disabled, false
}

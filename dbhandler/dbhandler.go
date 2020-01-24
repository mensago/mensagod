package dbhandler

// This module is for abstracting away all the messy details of interacting with the database.
// By doing so, it will be easier to add support for databases other than Postgresql. It will also
// eliminate cluttering up the otherwise-clean Go code with the ugly SQL queries.

import (
	"fmt"
	"log"
	"os"

	"database/sql"

	"github.com/spf13/viper"
)

var connected bool
var serverLog *log.Logger
var dbConn *sql.DB

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

	connString := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		viper.GetString("database.ip"), viper.GetString("database.port"),
		viper.GetString("database.user"), viper.GetString("database.password"),
		viper.GetString("database.name"))

	dbConn, err := sql.Open("postgres", connString)
	if err != nil {
		panic(err)
	}
	// Calling Ping() is required because Open() just validates the settings passed
	err = dbConn.Ping()
	if err != nil {
		panic(err)
	}
	connected = true
}

// IsConnected returns a boolean if it has successfully connected to the Anselus server database
func IsConnected() bool {
	return connected
}

// GetWorkspace checks to see if a workspace exists
func GetWorkspace(wid string) (string, bool) {
	row := dbConn.QueryRow(`SELECT status FROM iwkspc_main WHERE wid=$1`, wid)

	var widStatus string
	err := row.Scan(&widStatus)

	switch err {
	case sql.ErrNoRows:
		return "disabled", false
	case nil:
		return widStatus, true
	default:
		panic(err)
	}
}

// Disconnect shuts down the connection to the database server
func Disconnect() {
	if IsConnected() {
		dbConn.Close()
	}
}

package dbhandler

// This module is for abstracting away all the messy details of interacting with the database.
// By doing so, it will be easier to add support for databases other than Postgresql. It will also
// eliminate cluttering up the otherwise-clean Go code with the ugly SQL queries.

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

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

// Disconnect shuts down the connection to the database server
func Disconnect() {
	if IsConnected() {
		dbConn.Close()
	}
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

// LogFailure adds an entry to the database of a failure which needs tracked. This
// includes a type (workspace, password, recipient), the source (IP address, WID),
// and the timestamp of the failure.
// This function will check the server configuration and if the failure has
// exceeded the threshold for that type of failure, then a lockout timestamp will
// be set.
func LogFailure(failType string, source string, timestamp string) error {

	// failure type can only be one of three possible values
	switch failType {
	case "workspace", "password", "recipient":
		// do nothing -- everything's OK
	default:
		return errors.New("LogFailure: failure type must be 'workspace', 'password', or 'recipient',")
	}

	// source may only be an IP address or a UUID
	if source == "" {
		return errors.New("LogFailure: source may not be empty")
	} else if net.ParseIP(source) == nil && !ValidateUUID(source) {
		return errors.New(strings.Join([]string{"LogFailure: bad source ", timestamp}, ""))
	}

	// Timestamp must be ISO8601 without a timezone ('Z' suffix allowable)
	if len(timestamp) < 15 || len(timestamp) > 20 {
		return errors.New(strings.Join([]string{"LogFailure: bad timestamp ", timestamp}, ""))
	}
	tsPattern := regexp.MustCompile(`\d{4}-?\d{2}-?\d{2}[T ]\d{2}:?\d{2}:?\d{2}[zZ]?`)
	if !tsPattern.MatchString(timestamp) {
		return errors.New(strings.Join([]string{"LogFailure: bad timestamp ", timestamp}, ""))
	}

	// Now that the error-checking is out of the way, we can actually update the db. :)
	row := dbConn.QueryRow(`SELECT count FROM failure_log WHERE type=$1 AND source=$2`,
		failType, source)
	var failCount int
	err := row.Scan(&failCount)
	if err != nil {
		// Existing fail count. Increment value, check for lockout, and update table
		failCount++
		if failCount >= viper.GetInt("security.max_failures") {
			// Failure threshold exceeded. Calculate lockout timestamp and update db
			lockout := time.Now().UTC()
			delay, _ := time.ParseDuration(fmt.Sprintf("%dm",
				viper.GetInt64("security.lockout_delay_min")))
			lockout.Add(delay)
			sqlStatement := `
				UPDATE failure_log 
				SET count=$1, last_failure=$2, lockout_until=$3
				WHERE type=$4 AND source=$5`
			_, err = dbConn.Exec(sqlStatement, failCount, timestamp, lockout.Format(time.RFC3339),
				failType, source)
			if err != nil {
				panic(err)
			}
		} else {
			// Within threshold, so just update values
			sqlStatement := `
				UPDATE failure_log 
				SET count=$1, last_failure=$2 
				WHERE type=$3 AND source=$4`
			_, err = dbConn.Exec(sqlStatement, failCount, timestamp, failType, source)
			if err != nil {
				panic(err)
			}
		}
	} else {
		sqlStatement := `
		INSERT INTO failure_log(type, source, count, last_failure)
		VALUES($1, $2, $3, $4)`
		_, err = dbConn.Exec(sqlStatement, failType, source, failCount, timestamp)
		if err != nil {
			panic(err)
		}
	}

	return nil
}

// CheckLockout corresponds to LogFailure() in that it checks to see if said
// source has a lockout timestamp and returns it if there is or an empty string if not.
// It also has the added benefit of resetting a counter to 0 if there is an expired
// lockout for a particular source
func CheckLockout(failType string, source string) (string, error) {
	// TODO: Implement
	return "", nil
}

// ValidateUUID just returns whether or not a string is a valid UUID.
func ValidateUUID(uuid string) bool {
	pattern := regexp.MustCompile("[\\da-fA-F]{8}-?[\\da-fA-F]{4}-?[\\da-fA-F]{4}-?[\\da-fA-F]{4}-?[\\da-fA-F]{12}")
	if len(uuid) != 36 && len(uuid) == 32 {
		return false
	}
	return pattern.MatchString(uuid)
}

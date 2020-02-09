package dbhandler

// This module is for abstracting away all the messy details of interacting with the database.
// By doing so, it will be easier to add support for databases other than Postgresql. It will also
// eliminate cluttering up the otherwise-clean Go code with the ugly SQL queries.

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"database/sql"

	"github.com/darkwyrm/b85"
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

// LogFailure adds an entry to the database of a failure which needs tracked. This
// includes a type (workspace, password, recipient), the source (IP address, WID),
// and the timestamp of the failure.
// This function will check the server configuration and if the failure has
// exceeded the threshold for that type of failure, then a lockout timestamp will
// be set.
func LogFailure(failType string, wid string, source string) error {

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
		return errors.New(strings.Join([]string{"LogFailure: bad source ", source}, ""))
	}

	// Timestamp must be ISO8601 without a timezone ('Z' suffix allowable)
	timeString := time.Now().UTC().Format(time.RFC3339)

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
				WHERE type=$4 AND source=$5 AND wid=$6`
			_, err = dbConn.Exec(sqlStatement, failCount, timeString, lockout.Format(time.RFC3339),
				failType, source, wid)
			if err != nil {
				panic(err)
			}
		} else {
			// Within threshold, so just update values
			sqlStatement := `
				UPDATE failure_log 
				SET count=$1, last_failure=$2 
				WHERE type=$3 AND source=$4 and wid=$5`
			_, err = dbConn.Exec(sqlStatement, failCount, timeString, failType, source, wid)
			if err != nil {
				panic(err)
			}
		}
	} else {
		sqlStatement := `
		INSERT INTO failure_log(type, source, wid, count, last_failure)
		VALUES($1, $2, $3, $4, $5)`
		_, err = dbConn.Exec(sqlStatement, failType, source, wid, failCount, timeString)
		if err != nil {
			panic(err)
		}
	}

	return nil
}

// ValidateUUID just returns whether or not a string is a valid UUID.
func ValidateUUID(uuid string) bool {
	pattern := regexp.MustCompile("[\\da-fA-F]{8}-?[\\da-fA-F]{4}-?[\\da-fA-F]{4}-?[\\da-fA-F]{4}-?[\\da-fA-F]{12}")
	if len(uuid) != 36 && len(uuid) == 32 {
		return false
	}
	return pattern.MatchString(uuid)
}

// GenerateSessionString creates a randomly-generated device session string.
func GenerateSessionString(length int) string {

	byteList := make([]byte, 50)
	_, err := rand.Read(byteList)
	if err != nil {
		panic(err)
	}

	return b85.Encode(byteList)
}

// GetWorkspace checks to see if a workspace exists. If the workspace does exist,
// True is returned along with a string containing the workspace's status. If the
// workspace does not exist, it returns false and an empty string. The workspace
// status can be 'active', 'pending', or 'disabled'. Note that this function does
// not check the validity of the WID string passed to it. This should be done when
// the input is received from the user.
func GetWorkspace(wid string) (bool, string) {
	row := dbConn.QueryRow(`SELECT status FROM iwkspc_main WHERE wid=$1`, wid)

	var widStatus string
	err := row.Scan(&widStatus)

	switch err {
	case sql.ErrNoRows:
		return false, ""
	case nil:
		return true, widStatus
	default:
		panic(err)
	}
}

// CheckLockout corresponds to LogFailure() in that it checks to see if said
// source has a lockout timestamp and returns it if there is or an empty string if not.
// It also has the added benefit of resetting a counter to 0 if there is an expired
// lockout for a particular source
func CheckLockout(failType string, wid string, source string) (string, error) {
	row := dbConn.QueryRow(`SELECT lockout_until FROM failure_log 
		WHERE wid=$1 and source=$2`, wid)

	var locktime string
	err := row.Scan(&locktime)

	if err != nil {
		if err == sql.ErrNoRows {
			// No entry in the table, so obviously no lockout
			return "", nil
		}
		panic(err)
	}

	if len(locktime) < 1 {
		return locktime, nil
	}

	var lockstamp time.Time
	lockstamp, err = time.Parse(time.RFC3339, locktime)
	if err != nil {
		panic(err)
	}

	// If there is an expired lockout for this address, delete it
	if lockstamp.Before(time.Now().UTC()) {
		sqlStatement := `DELETE FROM failure_log
		WHERE failtype=$1 AND source=$2 AND lockout_until=$3 `
		_, err = dbConn.Exec(sqlStatement, failType, source, locktime)
		if err != nil {
			panic(err)
		}
		return "", nil
	}

	return locktime, nil
}

// CheckPassword checks a password hash against the one stored in the database. It returns true
// if the two hashes match. It does not perform any validity checking of the input--this should be
// done when the input is received from the user.
func CheckPassword(wid string, passhash string) (bool, error) {
	row := dbConn.QueryRow(`SELECT password FROM iwkspc_main WHERE wid=$1`, wid)

	var dbhash string
	err := row.Scan(&dbhash)
	if err != nil {
		return false, err
	}

	if strings.TrimSpace(passhash) != strings.TrimSpace(dbhash) {
		return false, nil
	}

	return true, nil
}

// SetWorkspaceStatus sets the status of a workspace. Valid values are "disabled", "active", and
// "approved". Although a workspace can also have a status of "awaiting", this state is internal
// to the dbhandler API and cannot be set directly.
func SetWorkspaceStatus(wid string, status string) error {
	realStatus := strings.ToLower(status)

	if realStatus == "awaiting" {
		return fmt.Errorf("awaiting is an internal-only workspace status")
	}
	if realStatus != "active" && realStatus != "disabled" && realStatus != "approved" {
		return fmt.Errorf("%s is not a valid status", realStatus)
	}
	if !ValidateUUID(wid) {
		return fmt.Errorf("%s is not a valid workspace ID", wid)
	}
	sqlStatement := `UPDATE iwkspc_main SET status=$1 WHERE wid=$2`
	var err error
	_, err = dbConn.Exec(sqlStatement, status, wid)
	return err
}

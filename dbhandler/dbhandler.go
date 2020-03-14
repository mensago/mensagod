package dbhandler

// This module is for abstracting away all the messy details of interacting with the database.
// By doing so, it will be easier to add support for databases other than Postgresql. It will also
// eliminate cluttering up the otherwise-clean Go code with the ugly SQL queries.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"database/sql"

	"github.com/darkwyrm/b85"
	"github.com/spf13/viper"
	"golang.org/x/crypto/argon2"
)

var (
	connected bool
	serverLog *log.Logger
	dbConn    *sql.DB
)

// This internal function is for turning a string into an Argon2 password hash.
func hashPassword(password string) string {
	mode := viper.GetString("security.password_security")

	var argonRAM, argonIterations, argonSaltLength, argonKeyLength uint32
	var argonThreads uint8

	if strings.ToLower(mode) == "enhanced" {
		// LUDICROUS SPEED! GO!
		argonRAM = 1073741824 // 1GB of RAM
		argonIterations = 10
		argonThreads = 8
		argonSaltLength = 24
		argonKeyLength = 48
	} else {
		argonRAM = 65536 // 64MB of RAM
		argonIterations = 3
		argonThreads = 4
		argonSaltLength = 16
		argonKeyLength = 32
	}

	salt := make([]byte, argonSaltLength)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}

	passhash := argon2.IDKey([]byte(password), salt, argonIterations, argonRAM, argonThreads,
		argonKeyLength)

	// Although base85 encoding is used wherever possible, base64 is used here because of a
	// potential collision: base85 uses the $ character and argon2 hash strings use it as a
	// field delimiter. Not a huge deal as it just uses a little extra disk storage and doesn't
	// get transmitted over the network
	passString := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonRAM, argonIterations, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(passhash))
	return passString
}

// This internal function takes a password and the Argon2 hash to verify against, gets the
// parameters from the hash, applies them to the supplied password, and returns whether or not
// they match and an error value
func verifyHash(password string, hashPass string) (bool, error) {
	splitValues := strings.Split(hashPass, "$")
	if len(splitValues) != 6 {
		return false, errors.New("Invalid Argon hash string")
	}

	var version int
	_, err := fmt.Sscanf(splitValues[2], "v=%d", &version)
	if err != nil {
		return false, err
	}
	if version != argon2.Version {
		return false, errors.New("Unsupported Argon version")
	}

	var ramUsage, iterations uint32
	var parallelism uint8
	_, err = fmt.Sscanf(splitValues[3], "m=%d,t=%d,p=%d", &ramUsage, &iterations, &parallelism)
	if err != nil {
		return false, err
	}

	var salt []byte
	salt, err = base64.RawStdEncoding.DecodeString(splitValues[4])
	if err != nil {
		return false, err
	}

	var savedHash []byte
	savedHash, err = base64.RawStdEncoding.DecodeString(splitValues[5])
	if err != nil {
		return false, err
	}

	passhash := argon2.IDKey([]byte(password), salt, iterations, ramUsage, parallelism,
		uint32(len(savedHash)))

	return (subtle.ConstantTimeCompare(passhash, savedHash) == 1), nil
}

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

	var err error
	dbConn, err = sql.Open("postgres", connString)
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
		sqlStatement := `INSERT INTO failure_log(type, source, wid, count, last_failure)
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
	if len(uuid) != 36 && len(uuid) != 32 {
		return false
	}
	return pattern.MatchString(uuid)
}

// GenerateRandomString creates a randomly-generated device session string.
func GenerateRandomString(length int) string {

	byteList := make([]byte, length)
	_, err := rand.Read(byteList)
	if err != nil {
		panic(err)
	}

	return b85.Encode(byteList)
}

// CheckLockout corresponds to LogFailure() in that it checks to see if said
// source has a lockout timestamp and returns it if there is or an empty string if not.
// It also has the added benefit of resetting a counter to 0 if there is an expired
// lockout for a particular source
func CheckLockout(failType string, wid string, source string) (string, error) {
	row := dbConn.QueryRow(`SELECT lockout_until FROM failure_log 
		WHERE wid=$1 and source=$2`, wid, source)

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

// SetPassword does just that: sets the password for a workspace. It returns a boolean state,
// indicating a match (or lack thereof) and an error state. It will take any input string of up to
// 64 characters and store it in the database.
func SetPassword(wid string, password string) error {
	if len(password) > 64 {
		return errors.New("Password string has a maximum 64 characters")
	}
	passHash := hashPassword(password)
	_, err := dbConn.Exec(`UPDATE iwkspc_main SET password=$1 WHERE wid=$2`, wid, passHash)
	return err
}

// CheckPassword checks a password hash against the one stored in the database. It returns true
// if the two hashes match. It does not perform any validity checking of the input--this should be
// done when the input is received from the user.
func CheckPassword(wid string, password string) (bool, error) {
	row := dbConn.QueryRow(`SELECT password FROM iwkspc_main WHERE wid=$1`, wid)

	var dbhash string
	err := row.Scan(&dbhash)
	if err != nil {
		return false, err
	}

	return verifyHash(password, dbhash)
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
	var err error
	_, err = dbConn.Exec(`UPDATE iwkspc_main SET status=$1 WHERE wid=$2`, status, wid)
	return err
}

// AddDevice is used for adding a device to a workspace. It generates a new session string for the
// device, adds it to the device table, sets the device status, and returns the session string for
// the new device.
func AddDevice(wid string, devid string) (string, error) {
	sessionString := GenerateRandomString(32)

	var err error
	sqlStatement := `INSERT INTO iwkspc_sessions(wid, devid, session_id) VALUES($1, $2, $3)`
	_, err = dbConn.Exec(sqlStatement, wid, devid, sessionString)
	if err != nil {
		return "", err
	}
	return sessionString, nil
}

// RemoveDevice removes a session string for a workspace. It returns true if successful and false
// if not.
func RemoveDevice(wid string, devid string) (bool, error) {
	if len(devid) != 40 {
		return false, errors.New("invalid session string")
	}
	_, err := dbConn.Exec(`DELETE FROM iwkspc_sessions WHERE wid=$1 AND devid=$2`, wid, devid)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// CheckDevice checks a session string on a workspace and returns true or false if there is a match.
func CheckDevice(wid string, devid string, sessionString string) (bool, error) {
	if len(sessionString) != 40 {
		return false, errors.New("invalid session string")
	}

	row := dbConn.QueryRow(`SELECT status FROM iwkspc_sessions WHERE wid=$1 AND 
		devid=$2 AND session_str=$3`, wid, devid, sessionString)

	var widStatus string
	err := row.Scan(&widStatus)

	switch err {
	case sql.ErrNoRows:
		return false, nil
	case nil:
		return true, nil
	default:
		return false, err
	}
}

// UpdateDevice takes a session string for a workspace, makes sure that it exists, generates a new
// one, replaces the old with the new, and returns the new session string. If successful, it
// returns true and the updated session string. On failure, false is returned alongside an empty
// string.
func UpdateDevice(wid string, devid string, sessionString string) (bool, string, error) {
	if len(sessionString) != 40 {
		return false, "", errors.New("invalid session string")
	}

	// Generate the new session string
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	newSessionString := b85.Encode(randomBytes)
	_, err = dbConn.Exec(`UPDATE iwkspc_sessions SET session_str=$1 WHERE wid=$2 AND 
		devid=$3 AND session_str=$4`, newSessionString, wid, devid, sessionString)

	switch err {
	case sql.ErrNoRows:
		return false, "", err
	case nil:
		return true, newSessionString, nil
	default:
		panic(err)
	}
}

// AddWorkspace is used for adding a workspace to a server. Upon failure, it returns the error
// state for the failure. It makes the necessary database modifications and creates the folder for
// the workspace in the filesystem. Note that this function is strictly for adding workspaces for
// individuals. Shared workspaces are not yet supported/implemented. Status may be 'active',
// 'pending', or 'disabled'.
func AddWorkspace(wid string, password string, status string) error {
	passString := hashPassword(password)

	var err error
	_, err = dbConn.Exec(`INSERT INTO iwkspc_main(wid, password, status) VALUES($1, $2, $3)`,
		wid, passString, status)
	return err
}

// RemoveWorkspace deletes a workspace. It returns an error if unsuccessful.
func RemoveWorkspace(wid string) error {
	var sqlCommands = []string{
		`DELETE FROM iwkspc_main WHERE wid=$1`,
		`DELETE FROM iwkspc_folders WHERE wid=$1`,
		`DELETE FROM iwkspc_sessions WHERE wid=$1`,
	}
	for _, sqlCmd := range sqlCommands {
		_, err := dbConn.Exec(sqlCmd, wid)
		if err != nil {
			return err
		}
	}
	return nil
}

// CheckWorkspace checks to see if a workspace exists. If the workspace does exist,
// True is returned along with a string containing the workspace's status. If the
// workspace does not exist, it returns false and an empty string. The workspace
// status can be 'active', 'pending', or 'disabled'. Note that this function does
// not check the validity of the WID string passed to it. This should be done when
// the input is received from the user.
func CheckWorkspace(wid string) (bool, string) {
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

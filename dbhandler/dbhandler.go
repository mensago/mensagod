package dbhandler

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"time"

	"database/sql"

	"github.com/everlastingbeta/diceware"
	"github.com/lib/pq"
	"github.com/spf13/viper"
	ezn "gitlab.com/darkwyrm/goeznacl"
	"gitlab.com/darkwyrm/gostringlist"
	"gitlab.com/mensago/mensagod/fshandler"
	"gitlab.com/mensago/mensagod/keycard"
	"gitlab.com/mensago/mensagod/logging"
	"gitlab.com/mensago/mensagod/misc"
	"gitlab.com/mensago/mensagod/types"
)

var (
	connected bool
	dbConn    *sql.DB
)

// Connect utilizes the viper config system and connects to the specified database. Because
// problems in the connection are almost always fatal to the successful continuation of the server
// daemon, if there are problems, it logs the problem and exits the main process.
func Connect() {
	if viper.GetString("database.engine") != "postgresql" {
		logging.Write("Database password not set in config file. Exiting.")
		logging.Shutdown()
		os.Exit(1)
	}

	connString := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		viper.GetString("database.ip"), viper.GetString("database.port"),
		viper.GetString("database.user"), viper.GetString("database.password"),
		viper.GetString("database.name"))

	var err error
	dbConn, err = sql.Open("postgres", connString)
	if err != nil {
		logging.Writef("Failed to open database connection. Exiting. Error: %s", err.Error())
		logging.Shutdown()
		os.Exit(1)
	}
	// Calling Ping() is required because Open() just validates the settings passed
	err = dbConn.Ping()
	if err != nil {
		logging.Writef("Failed to open database connection. Exiting. Error: %s", err.Error())
		logging.Shutdown()
		os.Exit(1)
	}
	connected = true
}

func ConnectWithString(connString string) {
	var err error
	dbConn, err = sql.Open("postgres", connString)
	if err != nil {
		logging.Writef("Failed to open database connection. Exiting. Error: %s", err.Error())
		logging.Shutdown()
		os.Exit(1)
	}
	// Calling Ping() is required because Open() just validates the settings passed
	err = dbConn.Ping()
	if err != nil {
		logging.Writef("Failed to open database connection. Exiting. Error: %s", err.Error())
		logging.Shutdown()
		os.Exit(1)
	}
	connected = true
}

// Disconnect shuts down the connection to the database server
func Disconnect() {
	if IsConnected() {
		dbConn.Close()
		connected = false
		dbConn = nil
	}
}

// IsConnected returns a boolean if it has successfully connected to the Mensago server database
func IsConnected() bool {
	return connected
}

// GetConnection returns a pointer to the database connection
func GetConnection() *sql.DB {
	if !IsConnected() {
		Connect()
	}
	return dbConn
}

func IsEmpty() bool {
	rows, err := dbConn.Query("SELECT table_name FROM information_schema.tables " +
		"WHERE table_schema = 'public' ORDER BY table_name;")
	return err != nil || rows == nil
}

// Reset clears all database to empty tables
func Reset() error {
	if !IsConnected() {
		Connect()
	}

	// Drop all tables
	_, err := dbConn.Exec(`
		DO $$ DECLARE
		r RECORD;
		BEGIN
			FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = current_schema()) LOOP
				EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
			END LOOP;
		END $$;
	`)
	if err != nil {
		return err
	}

	sqlCmds := []string{
		`CREATE TABLE workspaces(rowid SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL,
			uid VARCHAR(64), domain VARCHAR(255) NOT NULL, wtype VARCHAR(32) NOT NULL,
			status VARCHAR(16) NOT NULL, password VARCHAR(128));`,

		`CREATE TABLE aliases(rowid SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL,
			alias CHAR(292) NOT NULL);`,

		`CREATE TABLE iwkspc_folders(rowid SERIAL PRIMARY KEY, wid char(36) NOT NULL,
			serverpath VARCHAR(512) NOT NULL, clientpath VARCHAR(768) NOT NULL);`,

		`CREATE TABLE iwkspc_devices(rowid SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL,
			devid CHAR(36) NOT NULL, devkey VARCHAR(1000) NOT NULL,
			lastlogin VARCHAR(32) NOT NULL, status VARCHAR(16) NOT NULL);`,

		`CREATE TABLE quotas(rowid SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL,
			usage BIGINT, quota BIGINT);`,

		`CREATE TABLE failure_log(rowid SERIAL PRIMARY KEY, type VARCHAR(16) NOT NULL,
			id VARCHAR(36), source VARCHAR(36) NOT NULL, count INTEGER,
			last_failure TIMESTAMP NOT NULL, lockout_until TIMESTAMP);`,

		`CREATE TABLE passcodes(rowid SERIAL PRIMARY KEY, wid VARCHAR(36) NOT NULL UNIQUE,
			passcode VARCHAR(128) NOT NULL, expires TIMESTAMP NOT NULL);`,

		`CREATE TABLE prereg(rowid SERIAL PRIMARY KEY, wid VARCHAR(36) NOT NULL UNIQUE,
			uid VARCHAR(128) NOT NULL, domain VARCHAR(255) NOT NULL, regcode VARCHAR(128));`,

		`CREATE TABLE keycards(rowid SERIAL PRIMARY KEY, owner VARCHAR(292) NOT NULL,
			creationtime TIMESTAMP NOT NULL, index INTEGER NOT NULL,
			entry VARCHAR(8192) NOT NULL, fingerprint VARCHAR(96) NOT NULL);`,

		`CREATE TABLE orgkeys(rowid SERIAL PRIMARY KEY, creationtime TIMESTAMP NOT NULL,
			pubkey VARCHAR(7000), privkey VARCHAR(7000) NOT NULL,
			purpose VARCHAR(8) NOT NULL, fingerprint VARCHAR(96) NOT NULL);`,

		`CREATE TABLE updates(rowid SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL,
			update_type INTEGER, update_data VARCHAR(2048), unixtime BIGINT);`,
	}

	for _, cmd := range sqlCmds {
		_, err = dbConn.Exec(cmd)
		if err != nil {
			panic(err.Error())
		}
	}

	return nil
}

// LogFailure adds an entry to the database of a failure which needs tracked. This
// includes a type (workspace, password, recipient), the source (IP address, WID),
// and the timestamp of the failure.
// This function will check the server configuration and if the failure has
// exceeded the threshold for that type of failure, then a lockout timestamp will
// be set.
func LogFailure(failType string, wid types.UUID, sourceip string) error {
	if failType == "" {
		logging.Write("LogFailure(): empty fail type")
		return misc.ErrMissingArgument
	}

	if sourceip == "" {
		logging.Write("LogFailure(): empty source IP")
		return misc.ErrMissingArgument
	} else if net.ParseIP(sourceip) == nil {
		logging.Writef("LogFailure(): bad source IP %s", sourceip)
		return misc.ErrBadArgument
	}

	// Timestamp must be ISO8601 without a timezone ('Z' suffix allowable)
	timeString := time.Now().UTC().Format(time.RFC3339)

	// Now that the error-checking is out of the way, we can actually update the db. :)
	row := dbConn.QueryRow(`SELECT count FROM failure_log WHERE type=$1 AND source=$2`,
		failType, sourceip)
	var failCount int
	err := row.Scan(&failCount)

	if err != nil {
		// No failures in the table yet.
		if err == sql.ErrNoRows {
			sqlStatement := `INSERT INTO failure_log(type, source, id, count, last_failure)
			VALUES($1, $2, $3, $4, $5)`
			_, err = dbConn.Exec(sqlStatement, failType, sourceip, wid.AsString(), failCount,
				timeString)
			if err != nil {
				logging.Write("dbhandler.LogFailure: failed to update failure log")
			}
		}
		return err
	}

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
			WHERE type=$4 AND source=$5 AND id=$6`
		_, err = dbConn.Exec(sqlStatement, failCount, timeString, lockout.Format(time.RFC3339),
			failType, sourceip, wid.AsString())
		if err != nil {
			logging.Write("dbhandler.LogFailure: failed to update failure log")
			return err
		}
	} else {
		// Within threshold, so just update values
		sqlStatement := `
			UPDATE failure_log 
			SET count=$1, last_failure=$2 
			WHERE type=$3 AND source=$4 and wid=$5`
		_, err = dbConn.Exec(sqlStatement, failCount, timeString, failType, sourceip, wid.AsString())
		if err != nil {
			logging.Write("dbhandler.LogFailure: failed to update failure log")
			return err
		}
	}

	return nil
}

// ResolveAddress returns the WID corresponding to an Mensago address.
func ResolveAddress(addr types.MAddress) (types.UUID, error) {

	if !addr.IsValid() {
		return "", misc.ErrInvalidAddress
	}

	if addr.IsWorkspace() {
		// If the address is a workspace address, then all we have to do is confirm that the
		// workspace exists -- workspace IDs are unique across an organization, not just a domain
		row := dbConn.QueryRow(`SELECT wtype FROM workspaces WHERE wid=$1`, addr.ID)
		var wtype string
		err := row.Scan(&wtype)

		if err != nil {
			if err == sql.ErrNoRows {
				// No entry in the table
				return "", misc.ErrNotFound
			}
			return "", err
		}

		if wtype == "alias" {
			row := dbConn.QueryRow(`SELECT wid FROM aliases WHERE wid=$1`, addr.ID)
			var targetAddr string
			err := row.Scan(&targetAddr)
			if err != nil {
				return "", err
			}

			return types.ToUUID(targetAddr), nil
		}
		return types.ToUUID(addr.ID), nil
	}

	row := dbConn.QueryRow(`SELECT wid,domain FROM workspaces WHERE uid=$1`, addr.ID)
	var wid, domain string

	err := row.Scan(&wid, &domain)
	if err != nil {
		if err == sql.ErrNoRows {
			// No entry in the table
			return "", misc.ErrNotFound
		}
		return "", err
	}

	return types.ToUUID(wid), nil
}

func ResolveWID(wid types.UUID) (types.WAddress, error) {
	var domain string
	row := dbConn.QueryRow(`SELECT domain FROM workspaces WHERE wid = $1`, wid)
	err := row.Scan(&domain)
	if err != nil {
		var out types.WAddress
		if err == sql.ErrNoRows {
			// No entry in the table
			return out, nil
		}
		return out, err
	}
	return types.WAddress{ID: wid, Domain: types.DomainT(domain)}, nil
}

// CheckLockout corresponds to LogFailure() in that it checks to see if said
// source has a lockout timestamp and returns it if there is or an empty string if not.
// It also has the added benefit of resetting a counter to 0 if there is an expired
// lockout for a particular source. The ID parameter is a string specific to the failure type.
// For example, for logins, it is the workspace ID. For preregistration codes, it is the IP
// address of the remote host.
func CheckLockout(failType string, id string, source string) (string, error) {
	row := dbConn.QueryRow(`SELECT lockout_until FROM failure_log 
		WHERE id=$1 and source=$2`, id, source)

	var locktime string
	err := row.Scan(&locktime)

	if err != nil {
		if err == sql.ErrNoRows {
			// No entry in the table, so obviously no lockout
			return "", nil
		}
		logging.Write("dbhandler.CheckLockout: db error")
		return "", err
	}

	if len(locktime) < 1 {
		return locktime, nil
	}

	var lockstamp time.Time
	lockstamp, err = time.Parse(time.RFC3339, locktime)
	if err != nil {
		logging.Write("dbhandler.CheckLockout: bad timestamp in database")
		return "", err
	}

	// If there is an expired lockout for this address, delete it
	if lockstamp.Before(time.Now().UTC()) {
		sqlStatement := `DELETE FROM failure_log
		WHERE failtype=$1 AND source=$2 AND lockout_until=$3 `
		_, err = dbConn.Exec(sqlStatement, failType, source, locktime)
		if err != nil {
			logging.Write("dbhandler.CheckLockout: couldn't remove lockout from db")
			return "", err
		}
		return "", nil
	}

	return locktime, nil
}

// CheckPasscode checks the validity of a workspace/passcode combination. This function will return
// an error of "expired" if the combination is valid but expired.
func CheckPasscode(wid types.UUID, passcode string) (bool, error) {
	var expires string
	row := dbConn.QueryRow(`SELECT expires FROM passcodes WHERE wid = $1 AND passcode = $2 `,
		wid.AsString(), passcode)
	err := row.Scan(&expires)
	if err != nil {
		if err == sql.ErrNoRows {
			// No entry in the table
			return false, nil
		}
		return false, err
	}

	// We made it this far, so the combination is valid. Is it expired?
	var codestamp time.Time
	codestamp, err = time.Parse("20060102T150405Z", expires)
	if err != nil {
		logging.Write("dbhandler.CheckPasscode: bad timestamp in database")
		return false, err
	}

	if codestamp.Before(time.Now().UTC()) {
		return true, misc.ErrExpired
	}

	return true, nil
}

// DeletePasscode deletes a workspace/passcode combination
func DeletePasscode(wid types.UUID, passcode string) error {
	_, err := dbConn.Exec(`DELETE FROM passcodes WHERE wid = $1 AND passcode = $2`,
		wid.AsString(), passcode)

	return err
}

// RemoveExpiredPasscodes removes any workspace/passcode combination entries which are expired
func RemoveExpiredPasscodes() error {
	_, err := dbConn.Exec(`DELETE FROM passcodes WHERE expires < CURRENT_TIMESTAMP`)

	return err
}

// ResetPassword adds a reset code combination to the database for later authentication by the
// user. All parameters are expected to be populated.
func ResetPassword(wid types.UUID, passcode string, expires string) error {
	_, err := dbConn.Exec(`DELETE FROM passcodes WHERE wid = $1`, wid.AsString())
	if err != nil {
		return err
	}

	_, err = dbConn.Exec(`INSERT INTO passcodes(wid, passcode, expires) VALUES($1, $2, $3)`,
		wid.AsString(), passcode, expires)

	return err
}

// SetPassword does just that: sets the password for a workspace. It returns a boolean state,
// indicating a match (or lack thereof) and an error state. It will take any input string of up to
// 64 characters and store it in the database.
func SetPassword(wid types.UUID, password string) error {
	if len(password) > 128 {
		return misc.ErrOutOfRange
	}
	passHash := ezn.HashPassword(password)
	_, err := dbConn.Exec(`UPDATE workspaces SET password=$1 WHERE wid=$2`, passHash, wid.AsString())
	return err
}

// CheckPassword checks a password hash against the one stored in the database. It returns true
// if the two hashes match. It does not perform any validity checking of the input--this should be
// done when the input is received from the user.
func CheckPassword(wid types.UUID, password string) (bool, error) {
	row := dbConn.QueryRow(`SELECT password FROM workspaces WHERE wid=$1`, wid.AsString())

	var dbhash string
	err := row.Scan(&dbhash)
	if err != nil {
		return false, err
	}

	return ezn.VerifyPasswordHash(password, dbhash)
}

// AddDevice is used for adding a device to a workspace. The initial last login is set to when
// this method is called because a new device is only at certain times, such as at registration
// or when a user logs into a workspace on a new device.
func AddDevice(wid types.UUID, devid types.UUID, devkey ezn.CryptoString, status string) error {
	timestamp := fmt.Sprintf("%d", time.Now().UTC().Unix())
	var err error
	sqlStatement := `INSERT INTO iwkspc_devices(wid, devid, devkey, lastlogin, status) ` +
		`VALUES($1, $2, $3, $4, $5)`
	_, err = dbConn.Exec(sqlStatement, wid.AsString(), devid.AsString(), devkey.AsString(),
		timestamp, status)
	if err != nil {
		return err
	}
	return nil
}

// RemoveDevice removes a device from a workspace. It returns true if successful and false if not.
func RemoveDevice(wid types.UUID, devid types.UUID) (bool, error) {
	if len(devid) != 40 {
		return false, misc.ErrBadArgument
	}
	_, err := dbConn.Exec(`DELETE FROM iwkspc_devices WHERE wid=$1 AND devid=$2`, wid.AsString(),
		devid.AsString())
	if err != nil {
		return false, nil
	}
	return true, nil
}

// CheckDevice checks if a device has been added to a workspace.
func CheckDevice(wid types.UUID, devid types.UUID, devkey ezn.CryptoString) (bool, error) {
	row := dbConn.QueryRow(`SELECT status FROM iwkspc_devices WHERE wid=$1 AND 
		devid=$2 AND devkey=$3`, wid.AsString(), devid.AsString(), devkey.AsString())

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

// UpdateDevice replaces a device's old key with a new one
func UpdateDevice(wid types.UUID, devid types.UUID, oldkey ezn.CryptoString,
	newkey ezn.CryptoString) error {
	_, err := dbConn.Exec(`UPDATE iwkspc_devices SET devkey=$1 WHERE wid=$2 AND 
		devid=$3 AND devkey=$4`, newkey.AsString(), wid.AsString(), devid.AsString(),
		oldkey.AsString())

	return err
}

// UpdateLastLogin sets the last login timestamp for a device
func UpdateLastLogin(wid types.UUID, devid types.UUID) error {
	_, err := dbConn.Exec(`UPDATE iwkspc_devices SET lastlogin=$1 WHERE wid=$2 AND 
		devid=$3`, time.Now().UTC().Unix(), wid.AsString(), devid.AsString())

	return err
}

// GetLastLogin gets the last time a device logged in UTC time, UNIX format
func GetLastLogin(wid types.UUID, devid types.UUID) (int64, error) {
	// TODO: Fix this query -- needs to use devid, too
	row := dbConn.QueryRow(`SELECT lastlogin FROM iwkspc_devices WHERE wid=$1`, wid.AsString())

	var lastlogin int64
	err := row.Scan(&lastlogin)

	switch err {
	case sql.ErrNoRows:
		break
	case nil:
		return lastlogin, nil
	case err.(*pq.Error):
		logging.Writef("dbhandler.CheckUserID: PostgreSQL error reading workspaces: %s",
			err.Error())
	default:
		logging.Writef("dbhandler.CheckUserID: unexpected error reading workspaces: %s",
			err.Error())
	}
	return -1, err
}

// CheckUserID works the same as CheckWorkspace except that it checks for user IDs
func CheckUserID(uid types.UserID) (bool, string) {
	row := dbConn.QueryRow(`SELECT status FROM workspaces WHERE uid=$1`, uid.AsString())

	var widStatus string
	err := row.Scan(&widStatus)

	switch err {
	case sql.ErrNoRows:
		break
	case nil:
		return true, widStatus
	case err.(*pq.Error):
		logging.Writef("dbhandler.CheckUserID: PostgreSQL error reading workspaces: %s",
			err.Error())
		return false, ""
	default:
		logging.Writef("dbhandler.CheckUserID: unexpected error reading workspaces: %s",
			err.Error())
		return false, ""
	}

	row = dbConn.QueryRow(`SELECT uid FROM prereg WHERE uid=$1`, uid.AsString())
	err = row.Scan(&widStatus)

	switch err {
	case sql.ErrNoRows:
		return false, ""
	case nil:
		return true, "approved"
	case err.(*pq.Error):
		logging.Writef("dbhandler.CheckUserID: PostgreSQL error reading prereg: %s",
			err.Error())
		return false, ""
	default:
		logging.Writef("dbhandler.CheckUserID: unexpected error reading prereg: %s",
			err.Error())
		return false, ""
	}
}

// PreregWorkspace preregisters a workspace, adding a specified wid to the database and returns
// a randomly-generated registration code needed to authenticate the first login. Registration
// codes are stored in the clear, but that's merely because if an attacker already has access to
// the server to see the codes, the attacker can easily create new workspaces.
func PreregWorkspace(wid types.UUID, uid types.UserID, domain types.DomainT,
	wordList *diceware.Wordlist, wordcount int) (string, error) {

	if len(wid) > 36 || len(uid) > 128 {
		return "", misc.ErrBadArgument
	}

	if uid.IsValid() {
		row := dbConn.QueryRow(`SELECT uid FROM prereg WHERE uid=$1`, uid.AsString())
		var hasuid string
		err := row.Scan(&hasuid)

		if hasuid != "" {
			return "", misc.ErrExists
		}

		switch err {
		case sql.ErrNoRows:
			break
		case err.(*pq.Error):
			logging.Writef("dbhandler.PreregWorkspace: PostgreSQL error reading prereg: %s",
				err.Error())
			return "", err
		default:
			logging.Writef("dbhandler.PreregWorkspace: unexpected error reading prereg: %s",
				err.Error())
			return "", err
		}
	}

	regcode, _ := diceware.RollWords(wordcount, " ", *wordList)

	_, err := dbConn.Exec(`INSERT INTO prereg(wid, uid, domain, regcode) VALUES($1, $2, $3, $4)`,
		wid.AsString(), uid.AsString(), domain.AsString(), regcode)

	return regcode, err
}

// CheckRegCode handles authenticating a host using a user/workspace ID and registration
// code provided by PreregWorkspace. Based on authentication it either returns the workspace ID
// (success) or an empty string (failure). An error is returned only if authentication was not
// successful. The caller is still responsible for performing the necessary steps to add the
// workspace to the database.
func CheckRegCode(addr types.MAddress, regcode string) (string, string, error) {
	var wid, uid string
	if addr.IsWorkspace() {
		row := dbConn.QueryRow(`SELECT wid,uid FROM prereg WHERE regcode = $1 AND domain = $2`,
			regcode, addr.Domain.AsString())
		err := row.Scan(&wid, &uid)
		if err != nil {
			if err == sql.ErrNoRows {
				// No entry in the table
				return "", "", misc.ErrNotFound
			}
			return "", "", err
		}

		if wid == addr.ID {
			return wid, uid, nil
		}
		return "", "", misc.ErrMismatch
	}

	row := dbConn.QueryRow(`SELECT wid,uid FROM prereg WHERE regcode = $1 AND uid = $2 `+
		`AND domain = $3`, regcode, addr.ID, addr.Domain.AsString())
	err := row.Scan(&wid, &uid)
	if err != nil {
		if err == sql.ErrNoRows {
			// No entry in the table
			return "", "", misc.ErrNotFound
		}
		return "", "", err
	}

	return wid, uid, nil
}

// DeleteRegCode removes preregistration data from the database.
func DeleteRegCode(addr types.MAddress, regcode string) error {

	var err error
	if addr.IsWorkspace() {
		_, err = dbConn.Exec(`DELETE FROM prereg WHERE wid = $1 AND regcode = $2 AND domain = $3`,
			addr.ID, regcode, addr.Domain.AsString())
	} else {
		_, err = dbConn.Exec(`DELETE FROM prereg WHERE uid = $1 AND regcode = $2 AND domain = $3`,
			addr.ID, regcode, addr.Domain.AsString())
	}

	return err
}

// GetOrgEntries pulls one or more entries from the database. If an end index is not desired, set
// it to 0. Passing a starting index of 0 will return the current entry for the organization.
func GetOrgEntries(startIndex int, endIndex int) ([]string, error) {
	out := make([]string, 0, 10)

	if startIndex < 1 {
		// If given a 0 or negative number, we return just the current entry.
		row := dbConn.QueryRow(`SELECT entry FROM keycards WHERE owner = 'organization' ` +
			`ORDER BY index DESC LIMIT 1`)

		var entry string
		err := row.Scan(&entry)
		if err == nil {
			out = append(out, entry)
		}
		return out, err

	} else if endIndex >= 1 {
		// Given both a start and end index
		if endIndex < startIndex {
			return out, nil
		}
		rows, err := dbConn.Query(`SELECT entry FROM keycards WHERE owner = 'organization' `+
			`AND index >= $1 AND index <= $2 ORDER BY index`, startIndex, endIndex)
		if err != nil {
			return out, err
		}
		defer rows.Close()

		for rows.Next() {
			var entry string
			err := rows.Scan(&entry)
			if err != nil {
				return out, err
			}
			out = append(out, entry)
		}

	} else {
		// Given just a start index
		rows, err := dbConn.Query(`SELECT entry FROM keycards WHERE owner = 'organization' `+
			`AND index >= $1 ORDER BY index`, startIndex)
		if err != nil {
			return out, err
		}
		defer rows.Close()

		for rows.Next() {
			var entry string
			err := rows.Scan(&entry)
			if err != nil {
				return out, err
			}
			out = append(out, entry)
		}

	}
	return out, nil
}

// GetUserEntries pulls one or more entries from the database. If an end index is not desired, set
// it to 0. Passing a starting index of 0 will return the current entry for the workspace specified.
func GetUserEntries(wid types.UUID, startIndex int, endIndex int) ([]string, error) {
	out := make([]string, 0, 10)

	if startIndex < 1 {
		// If given a 0 or negative number, we return just the current entry.
		row := dbConn.QueryRow(`SELECT entry FROM keycards WHERE owner = $1 `+
			`ORDER BY index DESC LIMIT 1`, wid)

		var entry string
		err := row.Scan(&entry)
		if err == nil {
			out = append(out, entry)
		}
		return out, err

	} else if endIndex >= 1 {
		// Given both a start and end index
		if endIndex < startIndex {
			return out, nil
		}
		rows, err := dbConn.Query(`SELECT entry FROM keycards WHERE owner = $1 `+
			`AND index >= $2 AND index <= $3 ORDER BY index`, wid.AsString(), startIndex, endIndex)
		if err != nil {
			return out, err
		}
		defer rows.Close()

		for rows.Next() {
			var entry string
			err := rows.Scan(&entry)
			if err != nil {
				return out, err
			}
			out = append(out, entry)
		}

	} else {
		// Given just a start index
		rows, err := dbConn.Query(`SELECT entry FROM keycards WHERE owner = $1 `+
			`AND index >= $2 ORDER BY index`, wid.AsString(), startIndex)
		if err != nil {
			return out, err
		}
		defer rows.Close()

		for rows.Next() {
			var entry string
			err := rows.Scan(&entry)
			if err != nil {
				return out, err
			}
			out = append(out, entry)
		}

	}
	return out, nil
}

// AddEntry adds an entry to the database. The caller is responsible for validation of *ALL* data
// passed to this command.
func AddEntry(entry *keycard.Entry) error {
	var owner string
	if entry.Fields["Type"] == "Organization" {
		owner = "organization"
	} else {
		owner = entry.Fields["Workspace-ID"]
	}

	var err error
	_, err = dbConn.Exec(`INSERT INTO keycards(owner, creationtime, index, entry, fingerprint) `+
		`VALUES($1, $2, $3, $4, $5)`, owner, entry.Fields["Timestamp"], entry.Fields["Index"],
		string(entry.MakeByteString(-1)), entry.Hash)
	return err
}

// GetUserKeycard obtains a user's entire keycard as a Keycard object
func GetUserKeycard(wid types.UUID) (keycard.Keycard, error) {
	var out keycard.Keycard
	out.Type = "User"
	out.Entries = make([]keycard.Entry, 0)

	err := loadKeycardEntries(&out, wid.AsString())
	return out, err
}

// GetOrgKeycard obtains a organization's entire keycard as a Keycard object
func GetOrgKeycard() (keycard.Keycard, error) {
	var out keycard.Keycard
	out.Type = "Organization"
	out.Entries = make([]keycard.Entry, 0)

	err := loadKeycardEntries(&out, "organization")
	return out, err
}

// loadKeycardEntries does all the heavy lifting of converting entries into a keycard for both
// Get*Keycard functions
func loadKeycardEntries(card *keycard.Keycard, owner string) error {
	if card == nil || owner == "" {
		return misc.ErrMissingArgument
	}

	rows, err := dbConn.Query(`SELECT entry FROM keycards WHERE owner = $1 ORDER BY index`, owner)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var entryString string
		err := rows.Scan(&entryString)
		if err != nil {
			return err
		}

		entry := keycard.NewUserEntry()
		err = entry.Set([]byte(entryString))
		if err != nil {
			return err
		}
		card.Entries = append(card.Entries, *entry)
	}

	return nil
}

// GetPrimarySigningPair obtains the organization's primary signing and verification keys
func GetPrimarySigningPair() (*ezn.SigningPair, error) {
	row := dbConn.QueryRow(`SELECT pubkey,privkey FROM orgkeys WHERE purpose = 'sign' ` +
		`ORDER BY rowid DESC LIMIT 1`)

	var verkey, signkey string
	err := row.Scan(&verkey, &signkey)
	if err == nil {
		keypair := ezn.NewSigningPair(ezn.NewCS(verkey), ezn.NewCS(signkey))
		return keypair, nil
	}
	return nil, err
}

// GetEncryptionPair returns the organization's encryption keypair as an EncryptionPair
func GetEncryptionPair() (*ezn.EncryptionPair, error) {
	row := dbConn.QueryRow(`SELECT pubkey,privkey FROM orgkeys WHERE purpose = 'encrypt' ` +
		`ORDER BY rowid DESC LIMIT 1`)

	var pubkey, privkey string
	err := row.Scan(&pubkey, &privkey)
	if err == nil {
		keypair := ezn.NewEncryptionPair(ezn.NewCS(pubkey), ezn.NewCS(privkey))
		return keypair, nil
	}
	return nil, err
}

// GetAliases returns a StringList containing the aliases pointing to the specified WID
func GetAliases(wid types.UUID) (gostringlist.StringList, error) {
	var out gostringlist.StringList
	rows, err := dbConn.Query(`SELECT alias FROM alias WHERE wid=$1`, wid.AsString())
	if err != nil {
		return out, err
	}
	defer rows.Close()

	for rows.Next() {
		var entry string
		err := rows.Scan(&entry)
		if err != nil {
			return out, err
		}
		out.Append(entry)
	}
	return out, nil
}

// GetQuotaInfo returns the disk usage and quota size of a workspace in bytes
func GetQuotaInfo(wid types.UUID) (uint64, uint64, error) {
	row := dbConn.QueryRow(`SELECT usage,quota FROM quotas WHERE wid=$1`, wid.AsString())

	var dbUsage, dbQuota int64
	var outUsage, outQuota uint64
	err := row.Scan(&dbUsage, &dbQuota)

	switch err {
	case sql.ErrNoRows:
		outUsage, err = fshandler.GetFSProvider().GetDiskUsage("/ wsp " + wid.AsString())
		if err != nil {
			return 0, 0, err
		}
		return outUsage, outQuota, SetQuotaUsage(wid, outUsage)
	case nil:
		if dbUsage >= 0 {
			return uint64(dbUsage), uint64(dbQuota), nil
		}
	case err.(*pq.Error):
		logging.Writef("dbhandler.GetQuotaUsage: PostgreSQL error: %s", err.Error())
		return 0, 0, err
	default:
		logging.Writef("dbhandler.GetQuotaUsage: unexpected error: %s", err.Error())
		return 0, 0, err
	}

	outUsage, err = fshandler.GetFSProvider().GetDiskUsage("/ wsp " + wid.AsString())
	if err != nil {
		return 0, 0, err
	}

	sqlStatement := `INSERT INTO quotas(wid, usage, quota)	VALUES($1, $2, $3)`
	_, err = dbConn.Exec(sqlStatement, wid, outUsage,
		viper.GetInt64("global.default_quota")*1_048_576)
	if err != nil {
		logging.Writef("dbhandler.GetQuotaUsage: failed to add quota entry to table: %s",
			err.Error())
	}

	return outUsage, outQuota, SetQuotaUsage(wid, outUsage)
}

// IsDomainLocal checks to see if the domain passed to it is managed by this server
func IsDomainLocal(domain types.DomainT) (bool, error) {
	if !domain.IsValid() {
		return false, misc.ErrBadArgument
	}

	row := dbConn.QueryRow(`SELECT domain FROM workspaces WHERE domain=$1`, domain.AsString())
	var tempString string
	err := row.Scan(&tempString)

	if err != nil {
		if err == sql.ErrNoRows {
			// No entry in the table
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// ModifyQuotaUsage modifies the disk usage by a relative amount, specified in bytes. Note that if
func ModifyQuotaUsage(wid types.UUID, amount int64) (uint64, error) {
	row := dbConn.QueryRow(`SELECT usage FROM quotas WHERE wid=$1`, wid)

	var dbUsage int64
	var out uint64
	err := row.Scan(&dbUsage)

	switch err {
	case sql.ErrNoRows:
		out, err = fshandler.GetFSProvider().GetDiskUsage("/ wsp " + wid.AsString())
		if err != nil {
			return 0, err
		}

		sqlStatement := `INSERT INTO quotas(wid, usage, quota)	VALUES($1, $2, $3)`
		_, err = dbConn.Exec(sqlStatement, wid.AsString(), out,
			viper.GetInt64("global.default_quota")*1_048_576)
		if err != nil {
			logging.Writef("dbhandler.ModifyQuotaUsage: failed to add quota entry to table: %s",
				err.Error())
		}
		return out, SetQuotaUsage(wid, out)
	case nil:
		// Keep going
	case err.(*pq.Error):
		logging.Writef("dbhandler.ModifyQuotaUsage: PostgreSQL error: %s", err.Error())
		return 0, err
	default:
		logging.Writef("dbhandler.ModifyQuotaUsage: unexpected error: %s", err.Error())
		return 0, err
	}

	// Disk usage is lazily updated after each boot. If it has yet to be updated, the value in the
	// database will be negative
	if dbUsage < 0 {
		fsh := fshandler.GetFSProvider()
		out, err = fsh.GetDiskUsage("/ wsp " + wid.AsString())
		if err != nil {
			return 0, err
		}
		return out, SetQuotaUsage(wid, out)
	}

	newTotal := dbUsage + amount
	if newTotal < 0 {
		newTotal = 0
	}
	return uint64(newTotal), SetQuotaUsage(wid, uint64(newTotal))
}

// ResetQuotaUsage resets the disk quota usage count in the database for all workspaces
func ResetQuotaUsage() error {
	sqlStatement := `UPDATE quotas SET usage=-1`
	_, err := dbConn.Exec(sqlStatement)
	if err != nil {
		logging.Write("dbhandler.ResetQuotaUsage: failed to update reset disk quotas")
		return err
	}
	return nil
}

// SetQuota sets the disk quota for a workspace to the specified number of bytes
func SetQuota(wid types.UUID, quota uint64) error {
	sqlStatement := `UPDATE quotas SET quota=$1 WHERE wid=$2`
	result, err := dbConn.Exec(sqlStatement, quota, wid.AsString())
	if err != nil {
		logging.Writef("dbhandler.SetQuota: failed to update quota for %s: %s", wid.AsString(),
			err.Error())
		return err
	}

	rowcount, _ := result.RowsAffected()
	if rowcount == 0 {
		usage, err := fshandler.GetFSProvider().GetDiskUsage("/ wsp " + wid.AsString())
		if err != nil {
			return err
		}
		sqlStatement := `INSERT INTO quotas(wid, usage, quota)	VALUES($1, $2, $3)`
		_, err = dbConn.Exec(sqlStatement, wid.AsString(), usage, quota)
		if err != nil {
			logging.Writef("dbhandler.SetQuota: failed to add quota entry to table: %s",
				err.Error())
			return err
		}
	}
	return nil
}

// SetQuotaUsage sets the disk quota usage for a workspace to a specified number of bytes. If the
// usage has not been updated since boot, the total is ignored and the actual value from disk
// is used.
func SetQuotaUsage(wid types.UUID, total uint64) error {
	sqlStatement := `UPDATE quotas SET usage=$1 WHERE wid=$2`
	result, err := dbConn.Exec(sqlStatement, total, wid.AsString())
	if err != nil {
		logging.Writef("dbhandler.SetQuotaUsage: failed to update quota for %s: %s", wid,
			err.Error())
		return err
	}

	rowcount, _ := result.RowsAffected()
	if rowcount == 0 {
		usage, err := fshandler.GetFSProvider().GetDiskUsage("/ wsp " + wid.AsString())
		if err != nil {
			return err
		}

		sqlStatement := `INSERT INTO quotas(wid, usage, quota)	VALUES($1, $2, $3)`
		_, err = dbConn.Exec(sqlStatement, wid.AsString(), usage,
			viper.GetInt64("global.default_quota")*1_048_576)
		if err != nil {
			logging.Writef("dbhandler.SetQuotaUsage: failed to add quota entry to table: %s",
				err.Error())
		}
	}

	return nil
}

// ValidateUUID just returns whether or not a string is a valid UUID.
func ValidateUUID(uuid string) bool {
	pattern := regexp.MustCompile(`[\da-fA-F]{8}-?[\da-fA-F]{4}-?[\da-fA-F]{4}-?[\da-fA-F]{4}-?[\da-fA-F]{12}`)
	if len(uuid) != 36 && len(uuid) != 32 {
		return false
	}
	return pattern.MatchString(uuid)
}

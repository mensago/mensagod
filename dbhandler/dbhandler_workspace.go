package dbhandler

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"
	ezn "gitlab.com/darkwyrm/goeznacl"
	"gitlab.com/mensago/mensagod/logging"
	"gitlab.com/mensago/mensagod/misc"
	"gitlab.com/mensago/mensagod/types"
)

// AddWorkspace is used for adding a workspace to a server. Upon failure, it returns the error
// state for the failure. It makes the necessary database modifications and creates the folder for
// the workspace in the filesystem. Note that this function is strictly for adding workspaces for
// individuals. Shared workspaces are not yet supported/implemented. Status may be 'active',
// 'pending', or 'disabled'.
func AddWorkspace(wid string, uid string, domain string, password string, status string,
	wtype string) error {
	passString := ezn.HashPassword(password, false)

	// wid, uid, domain, wtype, status, password
	var err error
	_, err = dbConn.Exec(`INSERT INTO workspaces(wid, uid, domain, password, status, wtype) `+
		`VALUES($1, $2, $3, $4, $5, $6)`,
		wid, uid, domain, passString, status, wtype)
	return err
}

// CheckWorkspace checks to see if a workspace exists. If the workspace does exist,
// True is returned along with a string containing the workspace's status. If the
// workspace does not exist, it returns false and an empty string. The workspace
// status can be 'active', 'pending', or 'disabled'. Preregistered workspaces have the status
// 'approved'. Note that this function does not check the validity of the WID string passed to it.
// This should be done when the input is received from the user.
func CheckWorkspace(wid string) (bool, string) {
	row := dbConn.QueryRow(`SELECT status FROM workspaces WHERE wid=$1`, wid)

	var widStatus string
	err := row.Scan(&widStatus)

	switch err {
	case sql.ErrNoRows:
		break
	case nil:
		return true, widStatus
	case err.(*pq.Error):
		logging.Writef("dbhandler.CheckWorkspace: PostgreSQL error reading workspaces: %s",
			err.Error())
		return false, ""
	default:
		logging.Writef("dbhandler.CheckWorkspace: unexpected error reading workspaces: %s",
			err.Error())
		return false, ""
	}

	row = dbConn.QueryRow(`SELECT wid FROM prereg WHERE wid=$1`, wid)
	err = row.Scan(&widStatus)

	switch err {
	case sql.ErrNoRows:
		return false, ""
	case nil:
		return true, "approved"
	case err.(*pq.Error):
		logging.Writef("dbhandler.CheckWorkspace: PostgreSQL error reading prereg: %s",
			err.Error())
		return false, ""
	default:
		logging.Writef("dbhandler.CheckWorkspace: unexpected error reading prereg: %s",
			err.Error())
		return false, ""
	}
}

// IsAlias returns a bool if the specified workspace is an alias or a real account
func IsAlias(wid string) (bool, error) {
	row := dbConn.QueryRow(`SELECT alias FROM aliases WHERE wid=$1`, wid)

	var alias string
	err := row.Scan(&alias)

	switch err {
	case sql.ErrNoRows:
		break
	case nil:
		return true, nil
	case err.(*pq.Error):
		logging.Writef("dbhandler.IsAlias: PostgreSQL error: %s", err.Error())
		return false, err
	default:
		return false, err
	}
	return false, nil
}

// RemoveWorkspace deletes a workspace. It returns an error if unsuccessful. Note that this does
// not remove all information about the workspace. WIDs and UIDs may not be reused for security
// purposes, so the uid and wid attached to the workspace will remain in the database for this
// reason
func RemoveWorkspace(wid string) error {
	var sqlCommands = []string{
		`UPDATE workspaces SET password='-',status='deleted' WHERE wid=$1`,
		`DELETE FROM iwkspc_folders WHERE wid=$1`,
		`DELETE FROM quotas WHERE wid=$1`,
	}
	for _, sqlCmd := range sqlCommands {
		_, err := dbConn.Exec(sqlCmd, wid)
		if err != nil {
			return err
		}
	}
	return nil
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
	_, err = dbConn.Exec(`UPDATE workspaces SET status=$1 WHERE wid=$2`, status, wid)
	return err
}

// AddFolderEntry adds a mapping of a server path to an encrypted client path
func AddFolderEntry(wid types.UUID, serverPath string, clientPath ezn.CryptoString) error {

	// The dbhandler-level calls do only minimal validation
	if !wid.IsValid() || serverPath == "" || !clientPath.IsValid() {
		return misc.ErrBadArgument
	}

	row := dbConn.QueryRow(`SELECT wid FROM iwkspc_folders WHERE wid=$1 AND serverpath=$2`,
		wid.AsString(), serverPath)
	var tempStr string
	err := row.Scan(&tempStr)

	if err == nil {
		// Error will be nil if the entry already exists
		return misc.ErrExists
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	_, err = dbConn.Exec(`INSERT INTO iwkspc_folders(wid, serverpath, clientpath) `+
		`VALUES($1, $2, $3)`, wid.AsString(), serverPath, clientPath.AsString())
	return err
}

// RemoveFolderEntry deletes a folder mapping
func RemoveFolderEntry(wid types.UUID, serverPath string) error {
	if !wid.IsValid() || serverPath == "" {
		return misc.ErrBadArgument
	}

	row := dbConn.QueryRow(`SELECT wid FROM iwkspc_folders WHERE wid=$1 AND serverpath=$2`,
		wid.AsString(), serverPath)
	var tempStr string
	err := row.Scan(&tempStr)

	if !errors.Is(err, sql.ErrNoRows) {
		return misc.ErrNotFound
	}

	_, err = dbConn.Exec(`DELETE FROM iwkspc_folders WHERE wid=$1 AND serverpath=$2 `,
		wid.AsString(), serverPath)
	return err
}

package dbhandler

import (
	"database/sql"
	"errors"
	"regexp"
	"time"

	"github.com/darkwyrm/mensagod/fshandler"
	"github.com/darkwyrm/mensagod/logging"
	"github.com/darkwyrm/mensagod/misc"
	"github.com/lib/pq"
	"github.com/spf13/viper"
)

// Sync-related functions

type UpdateType int

const (
	// We start at 1 so that we know if the UpdateRecord struct is initialized or not
	UpdateCreate = iota + 1
	UpdateDelete
	UpdateMove
	UpdateRotate
	UpdateMkDir
	UpdateRmDir
)

var movePattern = regexp.MustCompile(
	`^/( wsp| out| tmp)?( [0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12})*` +
		`( new)?( [0-9]+\.[0-9]+\.` +
		`[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12})*\s+` +
		`/( wsp| out| tmp)?( [0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12})*` +
		`( new)?$`)

type UpdateRecord struct {
	ID   string
	Type UpdateType
	Data string
	Time int64
}

// AddSyncRecord adds a record to the update table
func AddSyncRecord(wid string, rec UpdateRecord) error {
	if !ValidateUUID(wid) || !ValidateUUID(rec.ID) {
		return misc.ErrInvalidID
	}

	switch rec.Type {
	case UpdateCreate, UpdateDelete, UpdateMkDir, UpdateRmDir:
		if !fshandler.ValidateMensagoPath(rec.Data) {
			return errors.New("bad record data")
		}
	case UpdateMove:
		if !movePattern.MatchString(rec.Data) {
			return errors.New("bad record data")
		}
	default:
		return errors.New("bad record type")
	}

	now := time.Now().UTC().Unix()

	_, err := dbConn.Exec(`INSERT INTO updates(rid, wid, update_type, update_data, unixtime) `+
		`VALUES($1, $2, $3, $4, $5)`,
		rec.ID, wid, rec.Type, rec.Data, now)
	if err != nil {
		logging.Write("dbhandler.AddSyncRecord: failed to add update record")
	}

	return err
}

// CountSyncRecords returns the number of sync records which occurred after the specified time
func CountSyncRecords(wid string, unixtime int64) (int64, error) {
	if !ValidateUUID(wid) {
		return -1, misc.ErrInvalidID
	}

	if unixtime < 0 {
		return -1, misc.ErrBadArgument
	}

	// A maximum of 75 records is returned because with the shortest possible updates, a maximum
	// of about 160 records can be returned in 8k. For more average update sizes (34 byte overhead,
	// 104 byte record), we can only fit about 78.
	row := dbConn.QueryRow(`SELECT COUNT(wid) FROM updates WHERE wid = $1 AND unixtime > $2`,
		wid, unixtime)
	var count int64
	err := row.Scan(&count)

	switch err {
	case sql.ErrNoRows:
		return 0, nil
	case nil:
		return count, nil
	case err.(*pq.Error):
		logging.Writef("dbhandler.CountSyncRecords: PostgreSQL error: %s", err.Error())
	}
	return -1, err
}

// GetSyncRecords gets all the update records after a specified period of time
func GetSyncRecords(wid string, unixtime int64) ([]UpdateRecord, error) {
	if !ValidateUUID(wid) {
		return nil, misc.ErrInvalidID
	}

	if unixtime < 0 {
		return nil, misc.ErrBadArgument
	}

	// A maximum of 75 records is returned because with the shortest possible updates, a maximum
	// of about 160 records can be returned in 8k. For more average update sizes (34 byte overhead,
	// 104 byte record), we can only fit about 78.
	rows, err := dbConn.Query(`SELECT rid,update_type,update_data,unixtime FROM updates `+
		`WHERE wid = $1 AND unixtime > $2 ORDER BY unixtime LIMIT 75`, wid, unixtime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]UpdateRecord, 0)
	for rows.Next() {
		var rec UpdateRecord
		err = rows.Scan(&rec.ID, &rec.Type, &rec.Data, &rec.Time)
		if err != nil {
			return out, err
		}
		out = append(out, rec)
	}

	return out, nil
}

func CullOldSyncRecords(wid string, unixtime int64) error {
	if !ValidateUUID(wid) {
		return misc.ErrInvalidID
	}

	if unixtime < 0 {
		return misc.ErrBadArgument
	}

	threshold := unixtime - (viper.GetInt64("performance.max_sync_age") * 86400)
	_, err := dbConn.Exec(`DELETE FROM updates WHERE unixtime - $1 > 0`, threshold)
	if err != nil {
		logging.Write("dbhandler.CullOldSyncRecords: failed to cull old records")
		return err
	}
	return nil
}

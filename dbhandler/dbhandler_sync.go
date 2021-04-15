package dbhandler

import (
	"errors"
	"regexp"
	"time"

	"github.com/darkwyrm/mensagod/logging"
	"github.com/spf13/viper"
)

// Sync-related functions

type UpdateType int

const (
	// We start at 1 so that we know if the UpdateRecord struct is initialized or not
	UpdateAdd = iota + 1
	UpdateDelete
	UpdateMove
	UpdateRotate
)

type UpdateRecord struct {
	Type UpdateType
	Data string
	Time int64
}

var movePattern = regexp.MustCompile(
	`^/( [0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12})*` +
		`( [0-9]+\.[0-9]+\.` +
		`[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12})*\s+` +
		`/( [0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12})*$`)

var filePathPattern = regexp.MustCompile(
	`^/( [0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12})*` +
		`( [0-9]+\.[0-9]+\.` +
		`[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12})+$`)

// AddSyncRecord adds a record to the update table
func AddSyncRecord(wid string, rec UpdateRecord) error {
	if !ValidateUUID(wid) {
		return errors.New("bad workspace id")
	}

	switch rec.Type {
	case UpdateAdd, UpdateDelete:
		if !filePathPattern.MatchString(rec.Data) {
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

	_, err := dbConn.Exec(`INSERT INTO updates(wid, update_type, update_data, unixtime) `+
		`VALUES($1, $2, $3, $4)`,
		wid, rec.Type, rec.Data, now)
	if err != nil {
		logging.Write("dbhandler.AddSyncRecord: failed to add update record")
	}

	return err
}

// GetSyncRecords gets all the update records after a specified period of time
func GetSyncRecords(wid string, unixtime int64) ([]UpdateRecord, error) {
	if !ValidateUUID(wid) {
		return nil, errors.New("bad workspace id")
	}

	if unixtime < 0 {
		return nil, errors.New("bad time")
	}

	rows, err := dbConn.Query(`SELECT update_type,update_data,unixtime FROM updates) `+
		`WHERE wid = $1 AND unixtime > $2`, wid, unixtime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]UpdateRecord, 0)
	for rows.Next() {
		var rec UpdateRecord
		err = rows.Scan(&rec.Type, &rec.Data, &rec.Time)
		if err != nil {
			return out, err
		}
		out = append(out, rec)
	}

	return out, nil
}

func CullOldSyncRecords(wid string, unixtime int64) error {
	if !ValidateUUID(wid) {
		return errors.New("bad workspace id")
	}

	if unixtime < 0 {
		return errors.New("bad time")
	}

	threshold := unixtime - (viper.GetInt64("global.max_sync_age") * 86400)
	_, err := dbConn.Exec(`DELETE FROM updates WHERE unixtime - $1 > 0`, threshold)
	if err != nil {
		logging.Write("dbhandler.CullOldSyncRecords: failed to cull old records")
		return err
	}
	return nil
}

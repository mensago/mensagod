package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/viper"
	ezn "gitlab.com/darkwyrm/goeznacl"
	"gitlab.com/mensago/mensagod/dbhandler"
	"gitlab.com/mensago/mensagod/fshandler"
	"gitlab.com/mensago/mensagod/logging"
	"gitlab.com/mensago/mensagod/messaging"
	"gitlab.com/mensago/mensagod/types"
)

func commandCancel(session *sessionState) {
	if session.LoginState != loginClientSession {
		session.LoginState = loginNoSession
	}
	session.SendQuickResponse(200, "OK", "")
}

func commandGetUpdates(session *sessionState) {
	// Command syntax:
	// GETUPDATES(Time)

	if !session.RequireLogin() {
		return
	}

	if !session.Message.HasField("Time") {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	unixtime, err := strconv.ParseInt(session.Message.Data["Time"], 10, 64)
	if err != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad time value")
		return
	}

	recordCount, err := dbhandler.CountSyncRecords(session.WID.AsString(), unixtime)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	records, err := dbhandler.GetSyncRecords(session.WID.AsString(), unixtime)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	// TODO: Update commandGetUpdates to no longer be limited by size.

	// The communication protocol code is now limited to 2GB, which *better* be a lot more than
	// necessary. If not, then there are *serious* problems on the server side in letting updates
	// accumulate beyond a certain threshold.

	// The code is set to return a maximum of 150 records. It's still very easily possible that
	// the response could be larger than 16K, so we need to put this thing together very carefully
	responseString, err := createUpdateResponse(&records, recordCount)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	session.WriteClient(responseString)
}

func commandIdle(session *sessionState) {
	// Command syntax:
	// IDLE(CountUpdates=-1)

	if !session.Message.HasField("CountUpdates") {
		session.SendQuickResponse(200, "OK", "")
		return
	}

	if !session.RequireLogin() {
		return
	}

	unixtime, err := strconv.ParseInt(session.Message.Data["CountUpdates"], 10, 64)
	if err != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad time value")
		return
	}

	recordCount, err := dbhandler.CountSyncRecords(session.WID.AsString(), unixtime)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	response := NewServerResponse(200, "OK")
	response.Data["UpdateCount"] = fmt.Sprintf("%d", recordCount)
	session.SendResponse(*response)
}

func commandSend(session *sessionState) {
	// Command syntax:
	// SEND(Size, Hash, Domain, TempName="", Offset=0)

	if !session.RequireLogin() {
		return
	}

	if session.Message.Validate([]string{"Size", "Hash", "Domain"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	// Both Name and Hash must be present when resuming
	if (session.Message.HasField("TempName") && !session.Message.HasField("Offset")) ||
		(session.Message.HasField("Offset") && !session.Message.HasField("TempName")) {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	var fileSize int64
	var fileHash ezn.CryptoString
	err := fileHash.Set(session.Message.Data["Hash"])
	if err != nil {
		session.SendQuickResponse(400, "BAD REQUEST", err.Error())
		return
	}

	fileSize, err = strconv.ParseInt(session.Message.Data["Size"], 10, 64)
	if err != nil || fileSize < 1 {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad file size")
		return
	}

	domain := types.ToDomain(session.Message.Data["Domain"])
	if !domain.IsValid() {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad domain")
	}

	var resumeOffset int64
	if session.Message.HasField("TempName") {
		if !fshandler.ValidateTempFileName(session.Message.Data["TempName"]) {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad file name")
			return
		}

		resumeOffset, err = strconv.ParseInt(session.Message.Data["Offset"], 10, 64)
		if err != nil || resumeOffset < 1 {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad resume offset")
			return
		}

		if resumeOffset > fileSize {
			session.SendQuickResponse(400, "BAD REQUEST", "Resume offset greater than file size")
			return
		}
	}

	// An administrator can dictate how large a file can be stored on the server

	if fileSize > int64(viper.GetInt("performance.max_message_size"))*0x10_0000 {
		session.SendQuickResponse(414, "LIMIT REACHED", "")
		return
	}

	// Arguments have been validated, do a quota check

	diskUsage, diskQuota, err := dbhandler.GetQuotaInfo(session.WID)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	if diskQuota != 0 && uint64(fileSize)+diskUsage > diskQuota {
		session.SendQuickResponse(409, "QUOTA INSUFFICIENT", "")
		return
	}

	fsp := fshandler.GetFSProvider()
	var tempHandle *os.File
	var tempName string
	if resumeOffset > 0 {
		tempName = session.Message.Data["TempName"]
		tempHandle, err = fsp.OpenTempFile(session.WID.AsString(), tempName, resumeOffset)

		if err != nil {
			session.SendQuickResponse(400, "BAD REQUEST", err.Error())
			return
		}

	} else {
		tempHandle, tempName, err = fsp.MakeTempFile(session.WID.AsString())
		if err != nil {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			return
		}
	}

	response := NewServerResponse(100, "CONTINUE")
	response.Data["TempName"] = tempName
	session.SendResponse(*response)

	if resumeOffset > 0 {
		_, err = session.ReadFileData(uint64(fileSize-resumeOffset), tempHandle)
	} else {
		_, err = session.ReadFileData(uint64(fileSize), tempHandle)
	}
	tempHandle.Close()
	if err != nil {
		// Transfer was interrupted. We won't delete the file--we will leave it so the client can
		// attempt to resume the upload later.
		return
	}

	hashMatch, err := fshandler.HashFile(strings.Join([]string{"/ tmp", session.WID.AsString(), tempName}, " "),
		fileHash)
	if err != nil {
		if err == ezn.ErrUnsupportedAlgorithm {
			session.SendQuickResponse(309, "UNSUPPORTED ALGORITHM", "")
		} else {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		}
		return
	}
	if !hashMatch {
		fsp.DeleteTempFile(session.WID.AsString(), tempName)
		session.SendQuickResponse(410, "HASH MISMATCH", "")
		return
	}

	address, err := dbhandler.ResolveWID(session.WID)
	if err != nil {
		logging.Writef("commandSend: Unable to resolve WID %s", err)
		fsp.DeleteTempFile(session.WID.AsString(), tempName)
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
	}

	fsp.InstallTempFile(session.WID.AsString(), tempName, "/ out")
	messaging.PushMessage(address.AsString(), domain.AsString(), "/ out "+tempName)
	session.SendQuickResponse(200, "OK", "")
}

func commandSendFast(session *sessionState) {
	// Command syntax:
	// SENDFAST(Size, Hash, Domain)

	if !session.RequireLogin() {
		return
	}

	if session.Message.Validate([]string{"Domain", "Message"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	domain := types.ToDomain(session.Message.Data["Domain"])
	if !domain.IsValid() {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad domain")
	}

	// Arguments have been validated, do a quota check

	diskUsage, diskQuota, err := dbhandler.GetQuotaInfo(session.WID)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	if diskQuota != 0 && MaxCommandLength+diskUsage > diskQuota {
		session.SendQuickResponse(409, "QUOTA INSUFFICIENT", "")
		return
	}

	fsp := fshandler.GetFSProvider()
	var tempHandle *os.File
	var tempName string
	tempHandle, tempName, err = fsp.MakeTempFile(session.WID.AsString())
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	tempHandle.Write([]byte(session.Message.Data["Message"]))

	tempHandle.Close()

	address, err := dbhandler.ResolveWID(session.WID)
	if err != nil {
		logging.Writef("commandSend: Unable to resolve WID %s", err)
		fsp.DeleteTempFile(session.WID.AsString(), tempName)
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
	}

	tempName, _ = fsp.InstallTempFile(session.WID.AsString(), tempName, "/ out")
	messaging.PushMessage(address.AsString(), domain.AsString(), "/ out "+tempName)
	session.SendQuickResponse(200, "OK", "")
}

func commandSetStatus(session *sessionState) {
	// Command syntax:
	// SETSTATUS(wid, status)

	if isAdmin, err := session.RequireAdmin(); err != nil || !isAdmin {
		return
	}

	if session.Message.Validate([]string{"Workspace-ID", "Status"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	wid, err := types.ToRandomID(session.Message.Data["Workspace-ID"])
	if err != nil || !wid.IsValid() {
		session.SendQuickResponse(400, "BAD REQUEST", "Invalid Workspace-ID")
		return
	}

	switch session.Message.Data["Status"] {
	case "active", "disabled", "approved", "suspended", "unpaid":
		break
	default:
		session.SendQuickResponse(400, "BAD REQUEST", "Invalid Status")
		return
	}

	if session.LoginState != loginClientSession {
		session.SendQuickResponse(401, "UNAUTHORIZED", "")
		return
	}

	adminAddress := types.ToMAddress("admin/" + viper.GetString("global.domain"))
	adminWid, err := dbhandler.ResolveAddress(adminAddress)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandPreregister: Error resolving address: %s", err)
		return
	}
	if !session.WID.Equals(adminWid) {
		session.SendQuickResponse(403, "FORBIDDEN", "Only admin can use this")
		return
	}

	if wid.AsString() == session.WID.AsString() {
		session.SendQuickResponse(403, "FORBIDDEN", "admin status can't be changed")
		return
	}

	err = dbhandler.SetWorkspaceStatus(wid.AsString(), session.Message.Data["Status"])
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandSetStatus: error setting workspace status: %s", err.Error())
		return
	}

	session.SendQuickResponse(200, "OK", "")
}

// createUpdateResponse takes a list of UpdateRecords and returns a ServerResponse which is smaller
// than the maximum response size of 16K. Great care must be taken here because the size of a
// Mensago path can vary greatly in size -- a workspace-level path is 38 bytes without any file
// name appended to it. These things add up quickly.
func createUpdateResponse(records *[]dbhandler.UpdateRecord, totalRecords int64) (string, error) {

	lookupTable := map[dbhandler.UpdateType]string{
		dbhandler.UpdateCreate:  "CREATE",
		dbhandler.UpdateDelete:  "DELETE",
		dbhandler.UpdateMove:    "MOVE",
		dbhandler.UpdateRotate:  "ROTATE",
		dbhandler.UpdateMkDir:   "MKDIR",
		dbhandler.UpdateRmDir:   "RMDIR",
		dbhandler.UpdateReplace: "REPLACE",
	}

	builder := strings.Builder{}
	if _, err := builder.WriteString(`{"Code":200,"Status":"OK","Info":"","Data":{`); err != nil {
		return "", err
	}
	if _, err := builder.WriteString(fmt.Sprintf(`"UpdateCount":"%d",`, totalRecords)); err != nil {
		return "", err
	}

	for i, record := range *records {

		recordData := fmt.Sprintf(`Update%d: "%s|%s|%s|%d",`, i, record.ID, lookupTable[record.Type],
			record.Data, record.Time)
		builder.WriteString(recordData)
	}
	builder.WriteString("}}")

	return builder.String(), nil
}

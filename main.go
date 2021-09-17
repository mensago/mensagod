package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/darkwyrm/mensagod/config"
	cs "github.com/darkwyrm/mensagod/cryptostring"
	"github.com/darkwyrm/mensagod/dbhandler"
	"github.com/darkwyrm/mensagod/fshandler"
	"github.com/darkwyrm/mensagod/kcresolver"
	"github.com/darkwyrm/mensagod/logging"
	"github.com/darkwyrm/mensagod/messaging"
	"github.com/darkwyrm/mensagod/misc"
	"github.com/darkwyrm/mensagod/types"
	"github.com/darkwyrm/mensagod/workerpool"
	"github.com/everlastingbeta/diceware"
	"github.com/spf13/viper"
)

// gDiceWordList is a copy of the word list for preregistration code generation
var gDiceWordList diceware.Wordlist

// MaxCommandLength is the maximum number of bytes an Mensago command is permitted to be. Note that
// bulk transfers are not subject to this restriction -- just the initial command.
const MaxCommandLength = 8192

var clientPool *workerpool.Pool

type greetingStruct struct {
	Name    string
	Version string
	Code    int
	Status  string
	Date    string
}

func main() {
	gDiceWordList = config.SetupConfig()
	messaging.InitDelivery()
	kcresolver.InitCache()
	clientPool = workerpool.New(viper.GetUint("performance.max_client_threads"))

	dbhandler.Connect()
	if !dbhandler.IsConnected() {
		fmt.Println("Unable to connect to database server. Quitting.")
		os.Exit(1)
	}
	defer dbhandler.Disconnect()

	listenString := viper.GetString("network.listen_ip") + ":" + viper.GetString("network.port")
	listener, err := net.Listen("tcp", listenString)
	if err != nil {
		fmt.Println("Error setting up listener: ", err.Error())
		os.Exit(1)
	} else {
		fmt.Println("Listening on " + listenString)
	}

	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting a connection: ", err.Error())
			os.Exit(1)
		}

		if clientPool.IsFull() {
			noCanHazData := greetingStruct{
				Name:    "Mensago",
				Version: "0.1",
				Code:    303,
				Status:  "SERVER UNAVAILABLE",
				Date:    time.Now().UTC().Format("20060102T150405Z"),
			}
			noCanHazMsg, _ := json.Marshal(noCanHazData)

			var session sessionState
			session.Connection = conn
			session.WriteClient(string(noCanHazMsg))

			continue
		}
		clientPool.Add(1)
		go connectionWorker(conn)
	}
}

func connectionWorker(conn net.Conn) {
	defer conn.Close()
	defer clientPool.Done()

	conn.SetReadDeadline(time.Now().Add(time.Minute * 30))
	conn.SetWriteDeadline(time.Now().Add(time.Minute * 10))

	var session sessionState
	session.Connection = conn
	session.LoginState = loginNoSession

	greetingData := greetingStruct{
		Name:    "Mensago",
		Version: "0.1",
		Code:    200,
		Status:  "OK",
		Date:    time.Now().UTC().Format("20060102T150405Z"),
	}
	greeting, _ := json.Marshal(greetingData)
	session.WriteClient(string(greeting))
	for {
		request, err := session.GetRequest()
		if err != nil {
			if err == misc.ErrJSONUnmarshal {
				session.SendQuickResponse(400, "BAD REQUEST", "JSON error")
				conn.SetReadDeadline(time.Now().Add(time.Minute * 30))
				conn.SetWriteDeadline(time.Now().Add(time.Minute * 10))
				continue
			}
			if err.Error() != "EOF" {
				break
			}
		}
		session.Message = request

		if request.Action == "QUIT" {
			break
		}
		processCommand(&session)

		if session.IsTerminating {
			break
		}
		conn.SetReadDeadline(time.Now().Add(time.Minute * 30))
		conn.SetWriteDeadline(time.Now().Add(time.Minute * 10))
	}
}

func processCommand(session *sessionState) {
	switch session.Message.Action {
	case "ADDENTRY":
		commandAddEntry(session)
	case "CANCEL":
		commandCancel(session)
	case "COPY":
		commandCopy(session)
	case "DELETE":
		commandDelete(session)
	case "DEVICE":
		commandDevice(session)
	case "DEVKEY":
		commandDevKey(session)
	case "DOWNLOAD":
		commandDownload(session)
	case "EXISTS":
		commandExists(session)
	case "GETQUOTAINFO":
		commandGetQuotaInfo(session)
	case "GETUPDATES":
		commandGetUpdates(session)
	case "GETWID":
		commandGetWID(session)
	case "IDLE":
		commandIdle(session)
	case "ISCURRENT":
		commandIsCurrent(session)
	case "LIST":
		commandList(session)
	case "LISTDIRS":
		commandListDirs(session)
	case "LOGIN":
		commandLogin(session)
	case "LOGOUT":
		commandLogout(session)
	case "MKDIR":
		commandMkDir(session)
	case "MOVE":
		commandMove(session)
	case "ORGCARD":
		commandOrgCard(session)
	case "PASSCODE":
		commandPasscode(session)
	case "PASSWORD":
		commandPassword(session)
	case "PREREG":
		commandPreregister(session)
	case "REGCODE":
		commandRegCode(session)
	case "REGISTER":
		commandRegister(session)
	case "RESETPASSWORD":
		commandResetPassword(session)
	case "RMDIR":
		commandRmDir(session)
	case "SELECT":
		commandSelect(session)
	case "SEND":
		commandSend(session)
	case "SENDFAST":
		commandSendFast(session)
	case "SETPASSWORD":
		commandSetPassword(session)
	case "SETQUOTA":
		commandSetQuota(session)
	case "SETSTATUS":
		commandSetStatus(session)
	case "UNREGISTER":
		commandUnregister(session)
	case "UPLOAD":
		commandUpload(session)
	case "USERCARD":
		commandUserCard(session)
	default:
		commandUnrecognized(session)
	}
}

func commandCancel(session *sessionState) {
	if session.LoginState != loginClientSession {
		session.LoginState = loginNoSession
	}
	session.SendQuickResponse(200, "OK", "")
}

func commandGetUpdates(session *sessionState) {
	// Command syntax:
	// GETUPDATES(Time)

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

	// The code is set to return a maximum of 75 records. It's still very easily possible that
	// the response could be larger than 8K, so we need to put this thing together very carefully
	responseString := createUpdateResponse(&records, recordCount)
	session.WriteClient(responseString)
}

func commandIdle(session *sessionState) {
	// Command syntax:
	// IDLE(CountUpdates=-1)

	if session.Message.HasField("CountUpdates") {
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
		return
	}
	session.SendQuickResponse(200, "OK", "")
}

func commandSend(session *sessionState) {
	// Command syntax:
	// SEND(Size, Hash, Domain, TempName="", Offset=0)

	if session.LoginState != loginClientSession {
		session.SendQuickResponse(401, "UNAUTHORIZED", "")
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
	var fileHash cs.CryptoString
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

	diskUsage, diskQuota, err := dbhandler.GetQuotaInfo(session.WID.AsString())
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
		if err == cs.ErrUnsupportedAlgorithm {
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

	address, err := dbhandler.ResolveWID(session.WID.AsString())
	if err != nil {
		logging.Writef("commandSend: Unable to resolve WID %s", err)
		fsp.DeleteTempFile(session.WID.AsString(), tempName)
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
	}

	fsp.InstallTempFile(session.WID.AsString(), tempName, "/ out")
	messaging.PushMessage(address, domain.AsString(), "/ out "+tempName)
	session.SendQuickResponse(200, "OK", "")
}

func commandSendFast(session *sessionState) {
	// Command syntax:
	// SENDFAST(Size, Hash, Domain)

	if session.LoginState != loginClientSession {
		session.SendQuickResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"Domain"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	domain := types.ToDomain(session.Message.Data["Domain"])
	if !domain.IsValid() {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad domain")
	}

	// Arguments have been validated, do a quota check

	diskUsage, diskQuota, err := dbhandler.GetQuotaInfo(session.WID.AsString())
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

	flatData, err := json.Marshal(session.Message)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "Unable to reflatten message")
		return
	}

	tempHandle.Write([]byte(flatData))

	tempHandle.Close()

	address, err := dbhandler.ResolveWID(session.WID.AsString())
	if err != nil {
		logging.Writef("commandSend: Unable to resolve WID %s", err)
		fsp.DeleteTempFile(session.WID.AsString(), tempName)
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
	}

	fsp.InstallTempFile(session.WID.AsString(), tempName, "/ out")
	messaging.PushMessage(address, domain.AsString(), "/ out "+tempName)
	session.SendQuickResponse(200, "OK", "")
}

func commandSetStatus(session *sessionState) {
	// Command syntax:
	// SETSTATUS(wid, status)

	if session.Message.Validate([]string{"Workspace-ID", "Status"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	wid := types.ToUUID(session.Message.Data["Workspace-ID"])
	if !wid.IsValid() {
		session.SendQuickResponse(400, "BAD REQUEST", "Invalid Workspace-ID")
		return
	}

	switch session.Message.Data["Status"] {
	case "active", "disabled", "approved":
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
	adminWid, err := dbhandler.ResolveAddress(adminAddress.GetAddress())
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandPreregister: Error resolving address: %s", err)
		return
	}
	if session.WID.AsString() != adminWid {
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
// than the maximum response size of 8K. Great care must be taken here because the size of a
// Mensago path can vary greatly in size -- a workspace-level path is 38 bytes without any file
// name appended to it. These things add up quickly.
func createUpdateResponse(records *[]dbhandler.UpdateRecord, totalRecords int64) string {

	lookupTable := map[dbhandler.UpdateType]string{
		dbhandler.UpdateAdd:    "CREATE",
		dbhandler.UpdateDelete: "DELETE",
		dbhandler.UpdateMove:   "MOVE",
		dbhandler.UpdateRotate: "ROTATE",
	}

	out := []string{`{"Code":200,"Status":"OK","Info":"","Data":{`}
	updateCountStr := fmt.Sprintf(`"UpdateCount":"%d",`, totalRecords)
	out = append(out, updateCountStr+`"Updates":[`)

	responseSize := 55 + len(updateCountStr)
	for i, record := range *records {

		recordString := fmt.Sprintf(`{"Type":"%s","Path":"%s","Time":"%d"}`,
			lookupTable[record.Type], record.Data, record.Time)

		if responseSize+len(recordString)+1 > MaxCommandLength {
			break
		}
		responseSize += len(recordString)
		if i > 0 {
			out = append(out, ","+recordString)
			responseSize++
		} else {
			out = append(out, recordString)
		}
	}
	out = append(out, "]}}")
	return strings.Join(out, "")
}

// logFailure is for logging the different types of client failures which can potentially
// terminate a session. If, after logging the failure, the limit is reached, this will return
// true, indicating that the current command handler needs to exit. The wid parameter may be empty,
// but should be supplied when possible. By doing so, it limits lockouts for an IP address to that
// specific workspace ID.
func logFailure(session *sessionState, failType string, wid string) (bool, error) {
	remoteip := strings.Split(session.Connection.RemoteAddr().String(), ":")[0]
	err := dbhandler.LogFailure(failType, wid, remoteip)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("logFailure: error logging failure: %s", err.Error())
		return true, err
	}

	// If lockTime is non-empty, it means that the client has exceeded the configured threshold.
	// At this point, the connection should be terminated. However, an empty lockTime
	// means that although there has been a failure, the count for this IP address is
	// still under the limit.
	lockTime, _ := getLockout(session, failType, wid)
	if len(lockTime) > 0 {
		response := NewServerResponse(405, "TERMINATED")
		response.Data["Lock-Time"] = lockTime
		session.SendResponse(*response)
		session.IsTerminating = true
		return true, nil
	}

	return false, nil
}

// isLocked checks to see if the client should be locked out of the session. It handles sending
// the appropriate message and returns true if the command handler should just exit.
func isLocked(session *sessionState, failType string, wid string) (bool, error) {
	lockTime, err := getLockout(session, failType, wid)
	if err != nil {
		return true, err
	}

	if len(lockTime) > 0 {
		response := NewServerResponse(407, "UNAVAILABLE")
		response.Data["Lock-Time"] = lockTime
		session.SendResponse(*response)
		return true, nil
	}

	return false, nil
}

func getLockout(session *sessionState, failType string, wid string) (string, error) {

	lockTime, err := dbhandler.CheckLockout(failType, wid, session.Connection.RemoteAddr().String())
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("getLockout: error checking lockout: %s", err.Error())
		return "", err
	}

	if len(lockTime) > 0 {
		response := NewServerResponse(407, "UNAVAILABLE")
		response.Data["Lock-Time"] = lockTime
		session.SendResponse(*response)
		return lockTime, nil
	}

	return "", nil
}

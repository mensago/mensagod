package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/darkwyrm/mensagod/config"
	"github.com/darkwyrm/mensagod/dbhandler"
	"github.com/darkwyrm/mensagod/fshandler"
	"github.com/darkwyrm/mensagod/logging"
	"github.com/everlastingbeta/diceware"
	_ "github.com/lib/pq"
	"github.com/spf13/viper"
)

// ServerLog is the global logging object
var ServerLog *log.Logger

// gDiceWordList is a copy of the word list for preregistration code generation
var gDiceWordList diceware.Wordlist

var ErrJSONUnmarshal = errors.New("unmarshalling failure")

// -------------------------------------------------------------------------------------------
// Types
// -------------------------------------------------------------------------------------------

// MaxCommandLength is the maximum number of bytes an Mensago command is permitted to be. Note that
// bulk transfers are not subject to this restriction -- just the initial command.
const MaxCommandLength = 8192

type loginStatus int

const (
	// Unauthenticated state
	loginNoSession loginStatus = iota
	// Client has requested a valid workspace. Awaiting password.
	loginAwaitingPassword
	// Client has submitted a valid password. Awaiting session ID.
	loginAwaitingSessionID
	// Client has successfully authenticated
	loginClientSession
)

type sessionState struct {
	PasswordFailures int
	Connection       net.Conn
	Message          ClientRequest
	LoginState       loginStatus
	IsTerminating    bool
	WID              string
	WorkspaceStatus  string
	CurrentPath      fshandler.LocalAnPath
}

// ClientRequest is for encapsulating requests from the client.
type ClientRequest struct {
	Action string
	Data   map[string]string
}

// ServerResponse is for encapsulating messages to the client. We use the request-response paradigm,
// so all messages will actually be responses. All responses require a message code and accompanying
// status string.
type ServerResponse struct {
	Code   int
	Status string
	Info   string
	Data   map[string]string
}

// NewServerResponse creates a new server response which is fully initialized and ready to use
func NewServerResponse(code int, status string) *ServerResponse {
	var r ServerResponse
	r.Code = code
	r.Status = status
	r.Data = make(map[string]string)
	return &r
}

// HasField is syntactic sugar for checking if a request contains a particular field.
func (r *ClientRequest) HasField(fieldname string) bool {
	_, exists := r.Data[fieldname]
	return exists
}

// Validate performs schema validation for the request. Given a slice of strings containing the
// required Data keys, it returns an error if any of them are missing. While HasField() can be
// used to accomplish the same task, Validate() is for ensuring that all required data fields in
// a client request exist in one call.
func (r *ClientRequest) Validate(fieldlist []string) error {
	for _, fieldname := range fieldlist {
		_, exists := r.Data[fieldname]
		if !exists {
			return fmt.Errorf("missing field %s", fieldname)
		}
	}
	return nil
}

// GetRequest reads a request from a client from the socket
func (s *sessionState) GetRequest() (ClientRequest, error) {
	var out ClientRequest
	buffer := make([]byte, MaxCommandLength)
	bytesRead, err := s.Connection.Read(buffer)
	if err != nil {
		ne, ok := err.(*net.OpError)
		if ok && ne.Timeout() {
			s.IsTerminating = true
			return out, errors.New("connection timed out")
		}

		if err.Error() != "EOF" {
			fmt.Println("Error reading from client: ", err.Error())
		}
		return out, err
	}

	err = json.Unmarshal(buffer[:bytesRead], &out)
	if err != nil {
		return out, ErrJSONUnmarshal
	}

	return out, nil
}

// SendResponse sends a JSON response message to the client
func (s sessionState) SendResponse(msg ServerResponse) (err error) {
	out, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	_, err = s.Connection.Write([]byte(out))
	return err
}

// SendStringResponse is a syntactic sugar command for quickly sending error responses. The Info
// field can contain additional information related to the return code
func (s sessionState) SendStringResponse(code int, status string, info string) (err error) {
	return s.SendResponse(ServerResponse{code, status, info, map[string]string{}})
}

func (s *sessionState) ReadClient() (string, error) {
	buffer := make([]byte, MaxCommandLength)
	bytesRead, err := s.Connection.Read(buffer)
	if err != nil {
		ne, ok := err.(*net.OpError)
		if ok && ne.Timeout() {
			s.IsTerminating = true
			return "", errors.New("connection timed out")
		}

		if err.Error() != "EOF" {
			fmt.Println("Error reading from client: ", err.Error())
		}
		return "", err
	}

	return strings.TrimSpace(string(buffer[:bytesRead])), nil
}

func (s sessionState) WriteClient(msg string) (n int, err error) {
	return s.Connection.Write([]byte(msg))
}

func (s *sessionState) ReadFileData(fileSize uint64, fileHandle *os.File) (uint64, error) {

	var totalRead uint64
	buffer := make([]byte, MaxCommandLength)

	for totalRead < fileSize {

		bytesRead, err := s.Connection.Read(buffer)
		if err != nil {
			ne, ok := err.(*net.OpError)
			if ok && ne.Timeout() {
				s.IsTerminating = true
				return 0, errors.New("connection timed out")
			}

			if err.Error() != "EOF" {
				fmt.Println("Error reading from client: ", err.Error())
			}
			return 0, err
		}

		fileHandle.Write(buffer[:bytesRead])
		totalRead += uint64(bytesRead)
	}

	return totalRead, nil
}

func (s *sessionState) SendFileData(path string, offset int64) (int64, error) {

	fsp := fshandler.GetFSProvider()

	fileSize, err := fsp.GetFileSize(path)
	if err != nil {
		return -1, err
	}

	var totalWritten int64
	buffer := make([]byte, MaxCommandLength)

	fileHandle, err := fsp.OpenFile(path)
	if err != nil {
		return -1, err
	}
	defer fsp.CloseFile(fileHandle)

	if offset > 0 {
		err := fsp.SeekFile(fileHandle, offset)
		if err != nil {
			return 0, err
		}
	}

	for totalWritten < fileSize {

		bytesRead, err := fsp.ReadFile(fileHandle, buffer)
		if err != nil {
			if err.Error() != "EOF" {
				fmt.Println("Error reading from file: ", err.Error())
			}
			return int64(totalWritten), err
		}

		bytesWritten, err := s.Connection.Write(buffer[:bytesRead])
		if err != nil {
			ne, ok := err.(*net.OpError)
			if ok && ne.Timeout() {
				s.IsTerminating = true
				return 0, errors.New("connection timed out")
			}

			if err.Error() != "EOF" {
				fmt.Println("Error writing to client: ", err.Error())
			}
			return totalWritten, err
		}

		totalWritten += int64(bytesWritten)
	}

	return totalWritten, nil
}

// -------------------------------------------------------------------------------------------
// Function Definitions
// -------------------------------------------------------------------------------------------

func main() {
	gDiceWordList = config.SetupConfig()

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
		go connectionWorker(conn)
	}
}

func connectionWorker(conn net.Conn) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Minute * 30))
	conn.SetWriteDeadline(time.Now().Add(time.Minute * 10))

	var session sessionState
	session.Connection = conn
	session.LoginState = loginNoSession

	session.WriteClient("{\"Name\":\"Mensago\",\"Version\":\"0.1\",\"Code\":200," +
		"\"Status\":\"OK\"}\r\n")
	for {
		request, err := session.GetRequest()
		if err != nil {
			if err == ErrJSONUnmarshal {
				session.SendStringResponse(400, "BAD REQUEST", "JSON error")
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
	case "NOOP":
		// Do nothing. Just resets the idle counter.
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
	session.SendStringResponse(200, "OK", "")
}

func commandGetUpdates(session *sessionState) {
	// Command syntax:
	// GETUPDATES(Time)

	if !session.Message.HasField("Time") {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	unixtime, err := strconv.ParseInt(session.Message.Data["Time"], 10, 64)
	if err != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Bad time value")
		return
	}

	records, err := dbhandler.GetSyncRecords(session.WID, unixtime)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	// The code is set to return a maximum of 75 records. It's still very easily possible that
	// the response could be larger than 8K, so we need to put this thing together very carefully
	responseString := createUpdateResponse(&records)
	session.WriteClient(responseString)
}

func commandSetStatus(session *sessionState) {
	// Command syntax:
	// SETSTATUS(wid, status)

	if session.Message.Validate([]string{"Workspace-ID", "Status"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	if !dbhandler.ValidateUUID(session.Message.Data["Workspace-ID"]) {
		session.SendStringResponse(400, "BAD REQUEST", "Invalid Workspace-ID")
		return
	}

	switch session.Message.Data["Status"] {
	case "active", "disabled", "approved":
		break
	default:
		session.SendStringResponse(400, "BAD REQUEST", "Invalid Status")
		return
	}

	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	adminAddress := "admin/" + viper.GetString("global.domain")
	adminWid, err := dbhandler.ResolveAddress(adminAddress)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandPreregister: Error resolving address: %s", err)
		return
	}
	if session.WID != adminWid {
		session.SendStringResponse(403, "FORBIDDEN", "Only admin can use this")
		return
	}

	if session.Message.Data["Workspace-ID"] == session.WID {
		session.SendStringResponse(403, "FORBIDDEN", "admin status can't be changed")
		return
	}

	err = dbhandler.SetWorkspaceStatus(session.Message.Data["Workspace-ID"],
		session.Message.Data["Status"])
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandSetStatus: error setting workspace status: %s", err.Error())
		return
	}

	session.SendStringResponse(200, "OK", "")
}

// createUpdateResponse takes a list of UpdateRecords and returns a ServerResponse which is smaller
// than the maximum response size of 8K. Great care must be taken here because the size of a
// Mensago path can vary greatly in size -- a workspace-level path is 38 bytes without any file
// name appended to it. These things add up quickly.
func createUpdateResponse(records *[]dbhandler.UpdateRecord) string {

	lookupTable := map[dbhandler.UpdateType]string{
		dbhandler.UpdateAdd:    "CREATE",
		dbhandler.UpdateDelete: "DELETE",
		dbhandler.UpdateMove:   "MOVE",
		dbhandler.UpdateRotate: "ROTATE",
	}

	out := []string{`{"Code":200,"Status":"OK","Info":"","Data":{"Updates":[`}
	responseSize := 55
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
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
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
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
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

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
	"gitlab.com/mensago/mensagod/dbhandler"
	"gitlab.com/mensago/mensagod/fshandler"
	"gitlab.com/mensago/mensagod/logging"
	"gitlab.com/mensago/mensagod/messaging"
	"gitlab.com/mensago/mensagod/misc"
	"gitlab.com/mensago/mensagod/msgapi"
	"gitlab.com/mensago/mensagod/types"
)

type loginStatus int

const (
	// Unauthenticated state
	loginNoSession loginStatus = iota

	// Client has requested a valid workspace. Awaiting password.
	loginAwaitingPassword

	// Client has submitted a valid password. Awaiting device ID.
	loginAwaitingDeviceID

	// Client has successfully authenticated
	loginClientSession
)

type sessionState struct {
	PasswordFailures int
	Connection       net.Conn
	Message          ClientRequest
	LoginState       loginStatus
	IsTerminating    bool
	WID              types.RandomID
	DevID            string
	WorkspaceStatus  string
	CurrentPath      fshandler.LocalMPath
	LastUpdateSent   int64
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
	buffer, err := msgapi.ReadMessage(s.Connection, time.Minute*30)
	if err != nil {
		ne, ok := err.(*net.OpError)
		if ok && ne.Timeout() {
			s.IsTerminating = true
			return out, misc.ErrTimedOut
		}

		if err.Error() != "EOF" {
			fmt.Println("Error reading from client: ", err.Error())
		}
		return out, err
	}

	err = json.Unmarshal(buffer, &out)
	if err != nil {
		return out, misc.ErrJSONUnmarshal
	}

	return out, nil
}

// SendResponse sends a JSON response message to the client
func (s *sessionState) SendResponse(msg ServerResponse) (err error) {
	if msg.Code == 200 {
		s.AppendUpdateField(&msg)
	}

	out, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return msgapi.WriteMessage(s.Connection, []byte(out), time.Minute*10)
}

// SendQuickResponse is a syntactic sugar command for quickly sending error responses. The Info
// field can contain additional information related to the return code
func (s *sessionState) SendQuickResponse(code int, status string, info string) (err error) {
	msg := ServerResponse{code, status, info, map[string]string{}}
	if code == 200 {
		s.AppendUpdateField(&msg)
	}
	return s.SendResponse(msg)
}

// AppendUpdateField handles push notifications to clients. If a `200 OK` success code is sent and
// the worker goroutine has not sent an update since that time, then this method appends the
// UpdateCount field to the response so that the device has been notified of pending updates
func (s *sessionState) AppendUpdateField(msg *ServerResponse) {
	if s.LoginState != loginClientSession {
		return
	}

	lastUpdate := messaging.LastWorkspaceUpdate(s.WID.AsString())

	// lastUpdate == -1 if the workspace has not received any updates yet. This doesn't happen
	// often, but it does happen to new workspaces.
	if lastUpdate == -1 || lastUpdate <= s.LastUpdateSent {
		return
	}

	updateCount, err := dbhandler.CountSyncRecords(s.WID.AsString(), s.LastUpdateSent)
	if err != nil {
		logging.Writef("Error counting updates for wid %s: %s", s.WID, err.Error())
		return
	}

	if updateCount > 0 {
		msg.Data["UpdateCount"] = fmt.Sprintf("%d", updateCount)
		s.LastUpdateSent = time.Now().UTC().Unix()
	}
}

// RequireLogin is just syntactic sugar that make checking for a logged-in session a little cleaner
func (s *sessionState) RequireLogin() bool {

	if s.LoginState != loginClientSession {
		s.SendQuickResponse(401, "UNAUTHORIZED", "Login required")
		return false
	}
	return true
}

// RequireAdmin checks to see if the session belongs to the administrator. If it doesn't, it sends a
// quick response to the client and returns the appropriate value
func (s *sessionState) RequireAdmin() (bool, error) {

	adminAddress, err := GetAdmin()
	if err != nil {
		s.SendQuickResponse(300, "INTERNAL SERVER ERROR", "IsAdmin")
		logging.Writef("RequireAdmin: Error resolving admin address: %s", err)
		return false, err
	}

	if s.LoginState != loginClientSession || !s.WID.Equals(adminAddress.ID) {
		s.SendQuickResponse(403, "FORBIDDEN", "Only admin can use this")
		return false, nil
	}

	return true, nil
}

// IsAdmin just checks if the session is the administrator
func (s *sessionState) IsAdmin() (bool, error) {

	adminAddress, err := GetAdmin()
	if err != nil {
		s.SendQuickResponse(300, "INTERNAL SERVER ERROR", "IsAdmin")
		logging.Writef("IsAdmin: Error resolving admin address: %s", err)
		return false, err
	}

	if s.LoginState != loginClientSession || !s.WID.Equals(adminAddress.ID) {
		return false, nil
	}

	return true, nil
}

func (s *sessionState) ReadClient() (string, error) {
	buffer := make([]byte, MaxCommandLength)
	bytesRead, err := s.Connection.Read(buffer)
	if err != nil {
		ne, ok := err.(*net.OpError)
		if ok && ne.Timeout() {
			s.IsTerminating = true
			return "", misc.ErrTimedOut
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
				return 0, misc.ErrTimedOut
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
				return 0, misc.ErrTimedOut
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

func GetAdmin() (types.WAddress, error) {

	var out types.WAddress

	var addr types.MAddress
	addr.IDType = 2
	addr.ID = "admin"
	addr.Domain = types.DomainT(viper.GetString("global.domain"))

	adminWid, err := dbhandler.ResolveAddress(addr)
	if err != nil {
		return out, err
	}

	out.ID = adminWid
	return out, nil
}

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/darkwyrm/mensagod/dbhandler"
	"github.com/darkwyrm/mensagod/fshandler"
	"github.com/darkwyrm/mensagod/logging"
	"github.com/darkwyrm/mensagod/messaging"
	"github.com/darkwyrm/mensagod/misc"
)

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
	DevID            string
	WorkspaceStatus  string
	CurrentPath      fshandler.LocalAnPath
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
	buffer := make([]byte, MaxCommandLength)
	bytesRead, err := s.Connection.Read(buffer)
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

	err = json.Unmarshal(buffer[:bytesRead], &out)
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

	_, err = s.Connection.Write([]byte(out))
	return err
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

	lastUpdate := messaging.LastWorkspaceUpdate(s.WID)

	// lastUpdate == -1 if the workspace has not received any updates yet. This doesn't happen
	// often, but it does happen to new workspaces.
	if lastUpdate == -1 || lastUpdate <= s.LastUpdateSent {
		return
	}

	updateCount, err := dbhandler.CountSyncRecords(s.WID, s.LastUpdateSent)
	if err != nil {
		logging.Writef("Error counting updates for wid %s: %s", s.WID, err.Error())
		return
	}

	if updateCount > 0 {
		msg.Data["UpdateCount"] = fmt.Sprintf("%d", updateCount)
		s.LastUpdateSent = time.Now().UTC().Unix()
	}
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
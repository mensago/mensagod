package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/darkwyrm/b85"

	"github.com/darkwyrm/server/dbhandler"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/spf13/viper"
)

// ServerLog is the global logging object
var ServerLog *log.Logger

// -------------------------------------------------------------------------------------------
// Types
// -------------------------------------------------------------------------------------------

// MaxCommandLength is the maximum number of bytes an Anselus command is permitted to be, including
// end-of-line terminator. Note that bulk transfers are not subject to this restriction -- just the
// initial command.
const MaxCommandLength = 1024

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
	Tokens           []string
	LoginState       loginStatus
	IsTerminating    bool
	WID              string
	WorkspaceStatus  string
}

func (s sessionState) WriteClient(msg string) (n int, err error) {
	return s.Connection.Write([]byte(msg))
}

// -------------------------------------------------------------------------------------------
// Function Definitions
// -------------------------------------------------------------------------------------------

func setupConfig() *os.File {
	// IP and port to listen on
	viper.SetDefault("network.listen_ip", "127.0.0.1")
	viper.SetDefault("network.port", "2001")

	// Database config
	viper.SetDefault("database.engine", "postgresql")
	viper.SetDefault("database.ip", "127.0.0.1")
	viper.SetDefault("database.port", "5432")
	viper.SetDefault("database.name", "anselus")
	viper.SetDefault("database.user", "anselus")
	viper.SetDefault("database.password", "")

	// Location of workspace data, server log
	switch runtime.GOOS {
	case "js", "nacl":
		fmt.Println("Javascript and NaCl are not supported platforms for Anselus Server.")
		os.Exit(1)
	case "windows":
		programData, success := os.LookupEnv("ProgramData")
		if !success {
			programData = "C:\\ProgramData"
		}

		viper.SetDefault("global.workspace_dir", filepath.Join(programData, "anselus"))
		viper.Set("global.log_dir", filepath.Join(programData, "anselus-server"))
		viper.SetConfigName("serverconfig")
		viper.AddConfigPath(filepath.Join(programData, "anselus-server"))
	default:
		viper.SetDefault("global.workspace_dir", "/var/anselus/")
		viper.Set("global.log_dir", "/var/log/anselus-server/")
		viper.SetConfigName("serverconfig")
		viper.AddConfigPath("/etc/anselus-server/")
	}

	// Account registration modes
	// public - Outside registration requests.
	// network - registration is public, but restricted to a subnet or single IP address
	// moderated - A registration request is sent and a moderator must approve the account
	//			   prior to its creation
	// private - an account can be created only by an administrator -- outside requests will bounce
	viper.SetDefault("global.registration", "private")

	// Subnet(s) used for network registration. Defaults to private networks only.
	viper.SetDefault("global.registration_subnet", "192.168.0.0/24, 172.16.0.0/12, 10.0.0.0/8")
	viper.SetDefault("global.registration_subnet6", "fe80::/10")

	// Default user workspace quota in MiB. 0 = no quota
	viper.SetDefault("global.default_quota", 0)

	// Delay after an unsuccessful login
	viper.SetDefault("security.failure_delay_sec", 3)

	// Max number of login failures before the connection is closed
	viper.SetDefault("security.max_failures", 5)

	// Lockout time (in minutes) after max_failures exceeded
	viper.SetDefault("security.lockout_delay_min", 15)

	// Delay (in minutes) the number of minutes which must pass before another account registration
	// can be requested from the same IP address -- for preventing registration spam/DoS.
	viper.SetDefault("security.registration_delay_min", 15)

	// Is a matching session key required for a device to have access?
	viper.SetDefault("security.device_checking", "on")

	// Resource usage for password hashing
	viper.SetDefault("security.password_security", "normal")

	// Read the config file
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Printf("Unable to locate config file. Exiting. Error: %s", err)
		os.Exit(1)
	}

	logLocation := filepath.Join(viper.GetString("global.log_dir"), "anselus-server.log")
	if _, err := os.Stat(viper.GetString("global.log_dir")); os.IsNotExist(err) {
		err = os.Mkdir(viper.GetString("global.log_dir"), 0600)
		if err != nil {
			panic(err)
		}
	}

	logHandle, err := os.OpenFile(logLocation, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Unable to open log file %s. Aborting.\n", logLocation)
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}
	defer logHandle.Close()
	ServerLog = log.New(logHandle, "anselus-server:", log.LstdFlags)

	_, err = os.Stat(viper.GetString("global.workspace_dir"))
	if os.IsNotExist(err) {
		err = os.Mkdir(viper.GetString("global.workspace_dir"), 0600)
		if err != nil {
			panic(err)
		}
	}

	if viper.GetString("database.password") == "" {
		ServerLog.Println("Database password not set in config file. Exiting.")
		fmt.Println("Database password not set in config file. Exiting.")
		os.Exit(1)
	}

	switch viper.GetString("global.registration") {
	case "private", "public", "network", "moderated":
		// Do nothing. Legitimate values.
	default:
		ServerLog.Println("Invalid registration mode in config file. Exiting.")
		fmt.Printf("Invalid registration mode '%s'in config file. Exiting.\n",
			viper.GetString("global.registration"))
		os.Exit(1)
	}

	if viper.GetInt("global.default_quota") < 0 {
		viper.Set("global.default_quota", 0)
		ServerLog.Println("Negative quota value in config file. Assuming zero.")
		fmt.Println("Negative quota value in config file. Assuming zero.")
	}

	if viper.GetInt("security.failure_delay_sec") > 60 {
		viper.Set("security.failure_delay_sec", 60)
		ServerLog.Println("Limiting maximum failure delay to 60.")
		fmt.Println("Limiting maximum failure delay to 60.")
	}

	if viper.GetInt("security.max_failures") < 1 {
		viper.Set("security.max_failures", 1)
		ServerLog.Println("Invalid login failure maximum. Setting to 1.")
		fmt.Println("Invalid login failure maximum. Setting to 1.")
	} else if viper.GetInt("security.max_failures") > 10 {
		viper.Set("security.max_failures", 10)
		ServerLog.Println("Limiting login failure maximum to 10.")
		fmt.Println("Limiting login failure maximum to 10.")
	}

	if viper.GetInt("security.lockout_delay_min") < 0 {
		viper.Set("security.lockout_delay_min", 0)
		ServerLog.Println("Negative login failure lockout time. Setting to zero.")
		fmt.Println("Negative login failure lockout time. Setting to zero.")
	}

	if viper.GetInt("security.registration_delay_min") < 0 {
		viper.Set("security.registration_delay_min", 0)
		ServerLog.Println("Negative registration delay. Setting to zero.")
		fmt.Println("Negative registration delay. Setting to zero.")
	}

	devChecking := strings.ToLower(viper.GetString("security.device_checking"))
	if devChecking != "on" && devChecking != "off" {
		viper.Set("security.devChecking", "on")
		ServerLog.Println("Invalid device checking value. Exiting.")
		fmt.Println("Invalid device checking value. Exiting.")
		os.Exit(1)
	}

	return logHandle
}

func main() {
	logHandle := setupConfig()
	defer logHandle.Close()

	dbhandler.Connect(ServerLog)
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

	buffer := make([]byte, MaxCommandLength)

	var session sessionState
	session.Connection = conn
	session.LoginState = loginNoSession

	pattern := regexp.MustCompile("\"[^\"]+\"|\"[^\"]+$|[\\S\\[\\]]+")

	session.WriteClient("Anselus v0.1\r\n200 OK\r\n")
	for {
		bytesRead, err := conn.Read(buffer)
		if err != nil {
			ne, ok := err.(*net.OpError)
			if ok && ne.Timeout() {
				session.IsTerminating = true
				break
			} else {
				if err.Error() != "EOF" {
					fmt.Println("Error reading from client: ", err.Error())
				}
				continue
			}
		}

		trimmedString := strings.TrimSpace(string(buffer[:bytesRead]))
		session.Tokens = pattern.FindAllString(trimmedString, -1)

		if len(session.Tokens) > 0 {
			if session.Tokens[0] == "QUIT" {
				break
			}
			processCommand(&session)
		}
		if session.IsTerminating {
			break
		}
		conn.SetReadDeadline(time.Now().Add(time.Minute * 30))
		conn.SetWriteDeadline(time.Now().Add(time.Minute * 10))
	}
}

func processCommand(session *sessionState) {
	switch session.Tokens[0] {
	/*
		Commands to Implement:
		COPY
		DELETE
		DELIVER
		DOWNLOAD
		GETREG
		GETUPDATES
		LIST
		MKDIR
		MOVE
		RESUME
		SELECT
		SEND
		SERVERID
		SERVERPWD
		SETADDR
		SETREG
		UNREGISTER
		UPLOAD
	*/
	case "DEVICE":
		commandDevice(session)
	case "EXISTS":
		commandExists(session)
	case "LOGIN":
		commandLogin(session)
	case "LOGOUT":
		commandLogout(session)
	case "NOOP":
		// Do nothing. Just resets the idle counter.
	case "PASSWORD":
		commandPassword(session)
	case "REGISTER":
		commandRegister(session)
	default:
		commandUnrecognized(session)
	}
}

func commandDevice(session *sessionState) {
	// Command syntax:
	// DEVICE <devid> <keytype> <key>

	if len(session.Tokens) != 4 || !dbhandler.ValidateUUID(session.Tokens[1]) ||
		session.LoginState != loginAwaitingSessionID {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	success, err := dbhandler.CheckDevice(session.WID, session.Tokens[1], session.Tokens[2],
		session.Tokens[3])
	if err != nil {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	if !success {
		if strings.ToLower(viper.GetString("security.device_checking")) == "on" {
			// TODO: implement device checking:
			// 1) Check to see if there are multiple devices
			// 2) If there are multiple devices, push out an authorization message.
			// 3) Record the session ID in the table as a pending device.
			// 4) Return 101 PENDING and close the connection
			// 5) Upon receipt of authorization approval, update the device status in the database
			// 6) Upon receipt of denial, log the failure and apply a lockout to the IP
		} else {
			err = dbhandler.AddDevice(session.WID, session.Tokens[1],
				session.Tokens[2], session.Tokens[3])
			if err != nil {
				ServerLog.Printf("Internal server error. commandRegister.AddDevice. Error: %s\n", err)
				session.WriteClient("300 INTERNAL SERVER ERROR\r\n")
			}
			session.WriteClient("200 OK %s\r\n")
			session.LoginState = loginClientSession
		}
	} else {
		// The device is part of the workspace already, so now we issue undergo a challenge-response
		// to ensure that the device really is authorized and the key wasn't stolen by an impostor

		// TODO: Implement
	}
}

func commandExists(session *sessionState) {
	// Command syntax:
	// EXISTS <path>

	if session.LoginState != loginClientSession {
		session.WriteClient("401 UNAUTHORIZED\r\n")
		return
	}

	if len(session.Tokens) < 2 {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	fsPath := filepath.Join(viper.GetString("global.workspace_dir"), session.WID,
		strings.Join(session.Tokens[1:], string(os.PathSeparator)))
	_, err := os.Stat(fsPath)
	if err != nil {
		if os.IsNotExist(err) {
			session.WriteClient("404 NOT FOUND\r\n")
		} else {
			session.WriteClient("300 INTERNAL SERVER ERROR\r\n")
		}
	} else {
		session.WriteClient("200 OK\r\n")
	}
}

func commandLogin(session *sessionState) {
	// Command syntax:
	// LOGIN PLAIN WORKSPACE_ID

	// PLAIN authentication is currently the only supported type, so a total of 3 tokens
	// are required for this command.
	if len(session.Tokens) != 3 || session.Tokens[1] != "PLAIN" || !dbhandler.ValidateUUID(session.Tokens[2]) ||
		session.LoginState != loginNoSession {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	wid := session.Tokens[2]
	var exists bool
	exists, session.WorkspaceStatus = dbhandler.CheckWorkspace(wid)
	if exists {
		lockTime, err := dbhandler.CheckLockout("workspace", wid, session.Connection.RemoteAddr().String())
		if err != nil {
			panic(err)
		}

		if len(lockTime) > 0 {
			lockTime, err = dbhandler.CheckLockout("password", wid, session.Connection.RemoteAddr().String())
			if err != nil {
				panic(err)
			}
		}

		if len(lockTime) > 0 {
			// The only time that lockTime with be greater than 0 is if the account
			// is currently locked.
			session.WriteClient(strings.Join([]string{"407 UNAVAILABLE", lockTime, "\r\n"}, " "))
			return
		}

	} else {
		dbhandler.LogFailure("workspace", "", session.Connection.RemoteAddr().String())

		lockTime, err := dbhandler.CheckLockout("workspace", wid, session.Connection.RemoteAddr().String())
		if err != nil {
			panic(err)
		}

		// If lockTime is non-empty, it means that the client has exceeded the configured threshold.
		// At this point, the connection should be terminated. However, an empty lockTime
		// means that although there has been a failure, the count for this IP address is
		// still under the limit.
		if len(lockTime) > 0 {
			session.WriteClient(strings.Join([]string{"405 TERMINATED", lockTime, "\r\n"}, " "))
			session.IsTerminating = true
		} else {
			session.WriteClient("404 NOT FOUND\r\n")
		}
		return
	}

	switch session.WorkspaceStatus {
	case "disabled":
		session.WriteClient("411 ACCOUNT DISABLED\r\n")
		session.IsTerminating = true
	case "awaiting":
		session.WriteClient("101 PENDING\r\n")
		session.IsTerminating = true
	case "active", "approved":
		session.LoginState = loginAwaitingPassword
		session.WID = wid
		session.WriteClient("100 CONTINUE\r\n")
	}
}

func commandPassword(session *sessionState) {
	// Command syntax:
	// PASSWORD <pwhash>

	// This command takes a numeric hash of the user's password and compares it to what is submitted
	// by the user.
	if len(session.Tokens) != 2 || len(session.Tokens[1]) > 150 ||
		session.LoginState != loginAwaitingPassword {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	match, err := dbhandler.CheckPassword(session.WID, session.Tokens[1])
	if err == nil {
		if match {
			session.LoginState = loginAwaitingSessionID
			session.WriteClient("100 CONTINUE\r\n")
			return
		}

		dbhandler.LogFailure("password", session.WID, session.Connection.RemoteAddr().String())

		lockTime, err := dbhandler.CheckLockout("password", session.WID,
			session.Connection.RemoteAddr().String())
		if err != nil {
			panic(err)
		}

		// If lockTime is non-empty, it means that the client has exceeded the configured threshold.
		// At this point, the connection should be terminated. However, an empty lockTime
		// means that although there has been a failure, the count for this IP address is
		// still under the limit.
		if len(lockTime) > 0 {
			session.WriteClient(strings.Join([]string{"405 TERMINATED", lockTime, "\r\n"}, " "))
			session.IsTerminating = true
		} else {
			session.WriteClient("402 AUTHENTICATION FAILURE\r\n")

			var d time.Duration
			delayString := viper.GetString("security.failure_delay_sec") + "s"
			d, err = time.ParseDuration(delayString)
			if err != nil {
				ServerLog.Printf("Bad login failure delay string %s. Sleeping 3s.", delayString)
				fmt.Printf("Bad login failure delay string: %s. Sleeping 3s.", err)
				d, err = time.ParseDuration("3s")
			}
			time.Sleep(d)
		}
	} else {
		session.WriteClient("400 BAD REQUEST\r\n")
	}
}

func commandLogout(session *sessionState) {
	// command syntax:
	// LOGOUT
	session.WriteClient("200 OK\r\n")
	session.IsTerminating = true
}

func commandRegister(session *sessionState) {
	// command syntax:
	// REGISTER <WID> <passwordHash> <algorithm> <devkey>

	if len(session.Tokens) != 5 || !dbhandler.ValidateUUID(session.Tokens[1]) {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	regType := strings.ToLower(viper.GetString("global.registration"))
	if regType == "private" {
		// If registration is set to private, registration must be done from the server itself.
		if session.Connection.RemoteAddr() != session.Connection.LocalAddr() {
			session.WriteClient("304 REGISTRATION CLOSED\r\n")
			return
		}
	}

	success, _ := dbhandler.CheckWorkspace(session.Tokens[1])
	if success {
		session.WriteClient("408 RESOURCE EXISTS\r\n")
		return
	}

	// TODO: Check number of recent registration requests from this IP

	var workspaceStatus string
	switch regType {
	case "network":
		// TODO: Check that remote address is within permitted subnet
		session.WriteClient("301 NOT IMPLEMENTED\r\n")
		return
	case "moderated":
		workspaceStatus = "pending"
	default:
		workspaceStatus = "active"
	}

	// Just some basic sanity checks on the password hash.
	if len(session.Tokens[2]) < 8 || len(session.Tokens[2]) > 120 {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	if session.Tokens[3] != "curve25519" {
		session.WriteClient("309 ENCRYPTION TYPE NOT SUPPORTED\r\n")
		return
	}

	// An encryption key can be basically anything for validation purposes, but we can at least
	// make sure that the encoding is valid.
	_, err := b85.Decode(session.Tokens[4])
	if err != nil {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	err = dbhandler.AddWorkspace(session.Tokens[1], session.Tokens[2], workspaceStatus)
	if err != nil {
		ServerLog.Printf("Internal server error. commandRegister.AddWorkspace. Error: %s\n", err)
		session.WriteClient("300 INTERNAL SERVER ERROR\r\n")
	}

	devid := uuid.New().String()
	err = dbhandler.AddDevice(session.Tokens[1], devid, session.Tokens[3], session.Tokens[4])
	if err != nil {
		ServerLog.Printf("Internal server error. commandRegister.AddDevice. Error: %s\n", err)
		session.WriteClient("300 INTERNAL SERVER ERROR\r\n")
	}

	if regType == "moderated" {
		session.WriteClient("101 PENDING")
	} else {
		session.WriteClient(fmt.Sprintf("200 OK %s\r\n", devid))
	}
}

func commandUnrecognized(session *sessionState) {
	// command used when not recognized
	session.WriteClient("400 BAD REQUEST\r\n")
}

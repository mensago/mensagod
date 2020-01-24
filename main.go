package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/darkwyrm/server/dbhandler"
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
}

func (s sessionState) WriteClient(msg string) (n int, err error) {
	return s.Connection.Write([]byte(msg))
}

const (
	// ErrorBadRequest - Bad command sent by client
	ErrorBadRequest = "400 BAD REQUEST"
	// ErrorUnauthorized - Client sent command which requires being logged in
	ErrorUnauthorized = "401 UNAUTHORIZED"
	// ErrorAuthFailure - Login failure
	ErrorAuthFailure = "402 AUTHENTICATION FAILURE"
	// ErrorForbidden - Client not allowed to perform action. Usually a permissions problem.
	ErrorForbidden = "403 FORBIDDEN"
	// ErrorNotFound - Resource requested not found (workspace, client item, folder, etc.)
	ErrorNotFound = "404 NOT FOUND"
)

// -------------------------------------------------------------------------------------------
// Function Definitions
// -------------------------------------------------------------------------------------------

func setupConfig() {
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

	// Location of workspace data
	viper.SetDefault("global.workspace_dir", "/var/anselus/")

	// Account registration modes
	// public - Outside registration requests.
	// network - registration is public, but restricted to a subnet or single IP address
	// moderated - A registration request is sent and a moderator must approve the account
	//			   prior to its creation
	// private - an account can be created only by an administrator -- outside requests will bounce
	viper.SetDefault("global.registration", "private")

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

	// Search for the config file
	viper.SetConfigName("serverconfig")
	viper.AddConfigPath("/etc/anselus-server/")
	err := viper.ReadInConfig()
	if err != nil {
		ServerLog.Printf("Unable to locate config file. Exiting. Error: %s", err)
		fmt.Printf("Unable to locate config file. Exiting. Error: %s", err)
		os.Exit(1)
	}

	if viper.GetString("database.password") == "" {
		ServerLog.Println("Database password not set in config file. Exiting.")
		fmt.Println("Database password not set in config file. Exiting.")
		os.Exit(1)
	}
}

func main() {
	logHandle, err := os.OpenFile("/var/log/anselus-server/anselus-server.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Unable to open log file /var/log/anselus.log. Aborting.")
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}
	defer logHandle.Close()
	ServerLog = log.New(logHandle, "anselus-server:", log.LstdFlags)

	setupConfig()

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
	buffer := make([]byte, MaxCommandLength)

	var session sessionState
	session.Connection = conn
	session.LoginState = loginNoSession

	pattern := regexp.MustCompile("\"[^\"]+\"|\"[^\"]+$|[\\S\\[\\]]+")
	for {
		_, err := conn.Read(buffer)
		if err != nil {
			fmt.Println("Error reading from client: ", err.Error())
			continue
		}

		trimmedString := strings.TrimSpace(string(buffer))
		session.Tokens = pattern.FindAllString(trimmedString, -1)

		if len(session.Tokens) > 0 {
			if session.Tokens[0] == "QUIT" {
				break
			}
			processCommand(&session)
		}
	}
}

func processCommand(session *sessionState) {
	switch session.Tokens[0] {
	/*
		Commands to Implement:

		COPY
		DELETE
		DELIVER
		DEVICE
		DOWNLOAD
		EXISTS
		GETUPDATES
		LIST
		LOGIN
		LOGOUT
		MKDIR
		MOVE
		PASSWORD
		REGISTER
		RESUME
		SELECT
		SEND
		SERVERID
		SERVERPWD
		SETADDR
		UNREGISTER
		UPLOAD
	*/
	case "LOGIN":
		commandLogin(session)
	default:
		fmt.Println(strings.Join(session.Tokens, " "))
	}
}

func commandLogin(session *sessionState) {
	// Command syntax:
	// LOGIN PLAIN WORKSPACE_ID

	// PLAIN authentication is currently the only supported type, so a total of 3 tokens
	// are required for this command.
	if len(session.Tokens) != 3 || session.Tokens[1] != "PLAIN" || !validateUUID(session.Tokens[2]) ||
		session.LoginState != loginNoSession {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	wkspcStatus, exists := dbhandler.GetWorkspace(session.Tokens[2])
	if !exists {
		// TODO: Log workspace lookup failure
		session.WriteClient("404 NOT FOUND\r\n")
		return
	}

	switch wkspcStatus {
	case "disabled":
		session.WriteClient("411 ACCOUNT DISABLED\r\n")
	case "awaiting":
		session.WriteClient("101 PENDING\r\n")
	case "active":
		session.LoginState = loginAwaitingPassword
		session.WriteClient("200 OK")
	}
}

func validateUUID(uuid string) bool {
	pattern := regexp.MustCompile("[\\da-fA-F]{8}-?[\\da-fA-F]{4}-?[\\da-fA-F]{4}-?[\\da-fA-F]{4}-?[\\da-fA-F]{12}")
	if len(uuid) != 36 && len(uuid) == 32 {
		return false
	}
	return pattern.MatchString(uuid)
}

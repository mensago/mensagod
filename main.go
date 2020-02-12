package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

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

	// Is a matching session key required for a device to have access?
	viper.SetDefault("security.device_checking", "on")

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

	switch viper.GetString("global.registration") {
	case "private", "public", "network", "moderated":
		// Do nothing. Legitimate values.
	default:
		ServerLog.Println("Invalid registration mode in config file. Exiting.")
		fmt.Println("Invalid registration mode in config file. Exiting.")
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
		// TODO: Implement idle connection timeout
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
		if session.IsTerminating {
			break
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
		DOWNLOAD
		EXISTS
		GETUPDATES
		LIST
		MKDIR
		MOVE
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
	case "DEVICE":
		commandDevice(session)
	case "LOGIN":
		commandLogin(session)
	case "LOGOUT":
		commandLogout(session)
	case "NOOP":
		// Do nothing. Just resets the idle counter.
	case "PASSWORD":
		commandPassword(session)
	default:
		fmt.Println(strings.Join(session.Tokens, " "))
	}
}

func commandDevice(session *sessionState) {
	// Command syntax:
	// DEVICE <sessionID>

	if len(session.Tokens) != 2 || session.LoginState != loginAwaitingSessionID {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	success, err := dbhandler.CheckDevice(session.WID, session.Tokens[1])
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
			newSessionString := dbhandler.AddDevice(session.WID)
			session.WriteClient(fmt.Sprintf("200 OK %s\r\n", newSessionString))
			session.LoginState = loginClientSession
		}
	} else {
		var newSessionString string
		success, newSessionString, err = dbhandler.UpdateDevice(session.WID, session.Tokens[1])
		if err == nil && success {
			session.WriteClient(fmt.Sprintf("200 OK %s\r\n", newSessionString))
			session.LoginState = loginClientSession
		} else {
			session.WriteClient("300 INTERNAL SERVER ERROR\r\n")
		}
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
	exists, session.WorkspaceStatus = dbhandler.GetWorkspace(wid)
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
		session.WriteClient("100 CONTINUE")
	}
}

func commandPassword(session *sessionState) {
	// Command syntax:
	// PASSWORD <pwhash>

	// This command takes a numeric hash of the user's password and compares it to what is submitted
	// by the user.
	if len(session.Tokens) != 2 || len(session.Tokens[1]) > 48 ||
		session.LoginState != loginAwaitingPassword {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	match, err := dbhandler.CheckPassword(session.WID, session.Tokens[1])
	if err == nil {
		if match {
			// Check to see if this is a preregistered account that has yet to be logged into.
			// If it is, return 200 OK and the next session ID.
			if session.WorkspaceStatus == "approved" {
				session.LoginState = loginClientSession
				session.WriteClient(strings.Join([]string{"200 OK",
					dbhandler.GenerateSessionString(0), "\r\n"}, " "))
				err = dbhandler.SetWorkspaceStatus(session.WID, "active")
				if err != nil {
					panic(nil)
				}
				return
			}

			// Regular account login
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

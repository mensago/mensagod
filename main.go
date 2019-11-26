package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/spf13/viper"
)

// ServerLog is the global logging object
var ServerLog *log.Logger

// MaxCommandLength is the maximum number of bytes an Anselus command is permitted to be, including
// end-of-line terminator. Note that bulk transfers are not subject to this restriction -- just the
// initial command.
const MaxCommandLength = 1024

func setupConfig() {
	// IP and port to listen on
	viper.SetDefault("listen_ip", "127.0.0.1")
	viper.SetDefault("port", "2001")

	// Location of workspace data
	viper.SetDefault("workspace_dir", "/var/anselus/")

	// Delay after an unsuccessful login
	viper.SetDefault("login_delay", 3)

	// Max number of login failures before the connection is closed
	viper.SetDefault("max_failures", 5)

	// Default user workspace quota. 0 = no quota
	viper.SetDefault("default_quota", 0)

	// Account registration modes
	// public - Outside registration requests.
	// moderated - A registration request is sent and a moderator must approve the account
	//			   prior to its creation
	// closed - an account can be created only by an administrator -- outside requests will bounce
	viper.SetDefault("registration_mode", "private")

	// Search for the config file
	viper.SetConfigName("serverconfig.toml")
	viper.AddConfigPath("/etc/anselus-server/")
	err := viper.ReadInConfig()
	if err != nil {
		ServerLog.Println("Unable to locate config file. Using defaults.")
		fmt.Println("Unable to locate config file. Using defaults.")
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

	// TODO: once config file implemented, remove this hard-coded value.
	listener, err := net.Listen("tcp", "127.0.0.1:2001")
	if err != nil {
		fmt.Println("Error setting up listener: ", err.Error())
		os.Exit(1)
	} else {
		fmt.Println("Listening on localhost:2001")
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
	buffer := make([]byte, MaxCommandLength)

	bytesReceived, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Error reading from client: ", err.Error())
	}

	echoMessage := "Message received: \n------------------\n"
	echoMessage += string(buffer[:bytesReceived-1])
	echoMessage += "\n"

	conn.Write([]byte(echoMessage))
	conn.Close()
}

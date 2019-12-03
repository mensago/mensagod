package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"server/dbhandler"

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
	viper.SetConfigName("serverconfig.toml")
	viper.AddConfigPath("/etc/anselus-server/")
	err := viper.ReadInConfig()
	if err != nil {
		ServerLog.Println("Unable to locate config file. Exiting.")
		fmt.Println("Unable to locate config file. Exiting.")
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

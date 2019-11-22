package main

import (
	"fmt"
	"net"
	"os"
)

// MaxCommandLength is the maximum number of bytes an Anselus command is permitted to be, including
// end-of-line terminator. Note that bulk transfers are not subject to this restriction -- just the
// initial command.
const MaxCommandLength = 1024

func main() {
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

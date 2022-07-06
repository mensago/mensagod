package msgapi

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func FrameSessionTestSetup(sync chan int, port string) {
	// Wait until the test is ready and then go from there
	<-sync
	time.Sleep(time.Millisecond * 100)

	senderconn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		panic(fmt.Sprintf("Error connecting to test server: %s", err.Error()))
	}

	err = WriteMessage(senderconn, []byte("ThisIsATestMessage"), time.Minute*5)
	if err != nil {
		panic(err)
	}
}

// TestFrameSession  and its corresponding setup function cover session setup and transmitting and
// receiving a single frame over the wire
func TestFrameSession(t *testing.T) {
	sync := make(chan int)
	go FrameSessionTestSetup(sync, "2999")

	listener, err := net.Listen("tcp", "127.0.0.1:2999")
	if err != nil {
		t.Fatalf("Error setting up listener: %s", err.Error())
	}
	defer listener.Close()

	sync <- 1
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Error accepting a connection: %s", err.Error())
	}
	defer conn.Close()

	data, err := ReadMessage(conn, time.Minute*5)
	if err != nil {
		t.Fatalf("Error receiving size test message: %s", err.Error())
	}

	if string(data) != "ThisIsATestMessage" {
		t.Fatalf("Data mismatch: %s", data)
	}
}

func ReadMultipartMessageSetup(sync chan int, port string) {
	// Wait until the test is ready and then go from there
	<-sync
	time.Sleep(time.Millisecond * 100)

	senderconn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		panic(fmt.Sprintf("Error connecting to test server: %s", err.Error()))
	}

	// The maximum buffer size is 65535, so we make a message that is just a little bit bigger. ;)
	message := make([]byte, 65547)
	for i, c := range []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		index := 2521 * i
		copy(message[index:index+101], []byte(strings.Repeat(string(c), 100)))
	}
	err = WriteMessage(senderconn, message, time.Minute*5)

	if err != nil {
		panic(err)
	}
}

// TestReadMultipartMessage uses the same setup function as TestWriteMultipartMessage to test
// both multipart sending and receiving code in the Packet class
func TestReadMultipartMessage1(t *testing.T) {
	sync := make(chan int)
	go ReadMultipartMessageSetup(sync, "3001")

	listener, err := net.Listen("tcp", "127.0.0.1:3001")
	if err != nil {
		t.Fatalf("Error setting up listener: %s", err.Error())
	}
	defer listener.Close()

	sync <- 1
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Error accepting a connection: %s", err.Error())
	}
	defer conn.Close()

	_, err = ReadMessage(conn, time.Minute*5)
	if err != nil {
		t.Fatalf("Failure to read WirePacket: %s", err.Error())
	}
}

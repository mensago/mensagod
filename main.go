package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/everlastingbeta/diceware"
	"github.com/spf13/viper"
	"gitlab.com/mensago/mensagod/config"
	"gitlab.com/mensago/mensagod/dbhandler"
	"gitlab.com/mensago/mensagod/kcresolver"
	"gitlab.com/mensago/mensagod/logging"
	"gitlab.com/mensago/mensagod/messaging"
	"gitlab.com/mensago/mensagod/misc"
	"gitlab.com/mensago/mensagod/types"
	"gitlab.com/mensago/mensagod/workerpool"
)

// gDiceWordList is a copy of the word list for preregistration code generation
var gDiceWordList diceware.Wordlist

// MaxCommandLength is the maximum number of bytes an Mensago command is permitted to be. Note that
// bulk transfers are not subject to this restriction -- just the initial command.
const MaxCommandLength = 65535

var clientPool *workerpool.Pool

type greetingStruct struct {
	Name    string
	Version string
	Code    int
	Status  string
	Date    string
}

func main() {

	handleArgs(os.Args)
	gDiceWordList = config.SetupConfig()
	messaging.InitDelivery()
	kcresolver.InitCache()
	clientPool = workerpool.New(viper.GetUint("performance.max_client_threads"))

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

		if clientPool.IsFull() {
			noCanHazData := greetingStruct{
				Name:    "Mensago",
				Version: "0.1",
				Code:    303,
				Status:  "SERVER UNAVAILABLE",
				Date:    time.Now().UTC().Format("20060102T150405Z"),
			}
			noCanHazMsg, _ := json.Marshal(noCanHazData)

			var session sessionState
			session.Connection = conn
			session.WriteClient(string(noCanHazMsg) + "\r\n")

			continue
		}
		id, _ := clientPool.Add()
		go connectionWorker(conn, id)
	}
}

func printUsage(args []string) {
	fmt.Printf("Usage: %s [options]\n\n"+
		"--setup            Performs first-time setup. This option is only used\n"+
		"                   by itself and WILL DELETE EXISTING DATA.\n\n"+
		"--config <path>    Specify the configuration file for the server to use.\n\n",
		path.Base(args[0]))
}

func handleArgs(args []string) {
	switch len(args) {
	case 1:
		return
	case 2:
		if args[1] == "--setup" {
			SetupConfigFile()
			os.Exit(0)
		}
	case 3:
		if args[1] == "--config" {
			if _, err := os.Open(args[2]); err != nil {
				fmt.Printf("Unable to open file %s: %s\n", args[2], err.Error())
				os.Exit(2)
			}
			config.StartupConfig.ConfigPath = args[2]
			return
		}
	}
	printUsage(args)
	os.Exit(0)
}

func connectionWorker(conn net.Conn, workerID uint64) {
	defer conn.Close()
	defer clientPool.Done(workerID)

	conn.SetReadDeadline(time.Now().Add(time.Minute * 30))
	conn.SetWriteDeadline(time.Now().Add(time.Minute * 10))

	var session sessionState
	session.Connection = conn
	session.LoginState = loginNoSession

	greetingData := greetingStruct{
		Name:    "Mensago",
		Version: "0.1",
		Code:    200,
		Status:  "OK",
		Date:    time.Now().UTC().Format("20060102T150405Z"),
	}
	greeting, _ := json.Marshal(greetingData)
	session.WriteClient(string(greeting) + "\r\n")

	for {
		request, err := session.GetRequest()
		if err != nil {
			if err == misc.ErrJSONUnmarshal {
				session.SendQuickResponse(400, "BAD REQUEST", "JSON error")
				conn.SetReadDeadline(time.Now().Add(time.Minute * 30))
				conn.SetWriteDeadline(time.Now().Add(time.Minute * 10))
				continue
			}

			// For now, break on any other error, but log any that aren't EOF
			if err.Error() != "EOF" {
				logging.Writef("connectionWorker: Unhandled error %s", err)
			}
			break
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
	case "GETDEVICEINFO":
		commandGetDeviceInfo(session)
	case "GETQUOTAINFO":
		commandGetQuotaInfo(session)
	case "GETUPDATES":
		commandGetUpdates(session)
	case "GETWID":
		commandGetWID(session)
	case "IDLE":
		commandIdle(session)
	case "ISCURRENT":
		commandIsCurrent(session)
	case "KEYPKG":
		commandKeyPkg(session)
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
	case "REMOVEDEVICEINFO":
		commandRemoveDeviceInfo(session)
	case "RESETPASSWORD":
		commandResetPassword(session)
	case "RMDIR":
		commandRmDir(session)
	case "SELECT":
		commandSelect(session)
	case "SEND":
		commandSend(session)
	case "SENDLARGE":
		commandSendLarge(session)
	case "SETDEVICEINFO":
		commandSetDeviceInfo(session)
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

// logFailure is for logging the different types of client failures which can potentially
// terminate a session. If, after logging the failure, the limit is reached, this will return
// true, indicating that the current command handler needs to exit. The wid parameter may be empty,
// but should be supplied when possible. By doing so, it limits lockouts for an IP address to that
// specific workspace ID.
func logFailure(session *sessionState, failType string, wid types.RandomID) (bool, error) {
	remoteip := strings.Split(session.Connection.RemoteAddr().String(), ":")[0]
	err := dbhandler.LogFailure(failType, wid, remoteip)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
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
func isLocked(session *sessionState, failType string, wid types.RandomID) (bool, error) {
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

func getLockout(session *sessionState, failType string, wid types.RandomID) (string, error) {

	lockTime, err := dbhandler.CheckLockout(failType, wid.AsString(),
		session.Connection.RemoteAddr().String())
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
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

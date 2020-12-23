package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/darkwyrm/anselusd/dbhandler"
	"github.com/darkwyrm/b85"
	"github.com/spf13/viper"
	"golang.org/x/crypto/nacl/box"
)

func commandDevice(session *sessionState) {
	// Command syntax:
	// DEVICE(Device-ID,Device-Key)

	session.Message.Validate([]string{"Device-ID", "Device-Key"})
	if !dbhandler.ValidateUUID(session.Message.Data["Device-ID"]) ||
		session.LoginState != loginAwaitingSessionID {
		session.SendStringResponse(400, "BAD REQUEST")
		return
	}

	success, err := dbhandler.CheckDevice(session.WID, session.Message.Data["Device-ID"],
		session.Message.Data["Device-Key"])
	if err != nil {
		session.SendStringResponse(400, "BAD REQUEST")
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
			// TODO: Check for paranoid mode and reject if enabled
			dbhandler.AddDevice(session.WID, session.Message.Data["Device-ID"], "CURVE25519",
				session.Message.Data["Device-Key"], "active")

			session.LoginState = loginClientSession
			session.SendStringResponse(200, "OK")
			return
		}
	} else {
		// The device is part of the workspace already, so now we issue undergo a challenge-response
		// to ensure that the device really is authorized and the key wasn't stolen by an impostor

		success, err = challengeDevice(session, "CURVE25519", session.Message.Data["Device-Key"])
		if success {
			session.LoginState = loginClientSession
			session.SendStringResponse(200, "OK")
		} else {
			dbhandler.LogFailure("device", session.WID, session.Connection.RemoteAddr().String())
			session.SendStringResponse(401, "UNAUTHORIZED")
		}
	}
}

func commandLogin(session *sessionState) {
	// Command syntax:
	// LOGIN(Login-Type,Workspace-ID)

	// PLAIN authentication is currently the only supported type
	if session.Message.Validate([]string{"Login-Type", "Workspace-ID"}) != nil ||
		session.Message.Data["Login-Type"] != "PLAIN" ||
		!dbhandler.ValidateUUID(session.Message.Data["Workspace-ID"]) ||
		session.LoginState != loginNoSession {

		session.SendStringResponse(400, "BAD REQUEST")
		return
	}

	wid := session.Message.Data["Workspace-ID"]
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
			// The account is locked if lockTime is greater than 0
			var response ServerResponse
			response.Code = 407
			response.Status = "UNAVAILABLE"
			response.Data["Lock-Time"] = lockTime
			session.SendResponse(response)
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
			var response ServerResponse
			response.Code = 404
			response.Status = "TERMINATED"
			response.Data["Lock-Time"] = lockTime
			session.SendResponse(response)
			session.IsTerminating = true
		} else {
			session.SendStringResponse(404, "NOT FOUND")
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
		session.SendStringResponse(100, "CONTINUE")
	default:
		session.SendStringResponse(300, "INTERNAL SERVER ERROR")
	}
}

func commandLogout(session *sessionState) {
	// command syntax:
	// LOGOUT
	session.SendStringResponse(200, "OK")
	session.IsTerminating = true
}

func commandPassword(session *sessionState) {
	// Command syntax:
	// PASSWORD(Password-Hash)

	// This command takes a numeric hash of the user's password and compares it to what is submitted
	// by the user.
	if !session.Message.HasField("Password-Hash") || session.LoginState != loginAwaitingPassword {
		session.SendStringResponse(400, "BAD REQUEST")
		return
	}

	match, err := dbhandler.CheckPassword(session.WID, session.Message.Data["Password-Hash"])
	if err == nil {
		if match {
			session.LoginState = loginAwaitingSessionID
			session.SendStringResponse(100, "CONTINUE")
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
			var response ServerResponse
			response.Code = 407
			response.Status = "UNAVAILABLE"
			response.Data["Lock-Time"] = lockTime
			session.SendResponse(response)
			session.IsTerminating = true
		} else {
			session.SendStringResponse(402, "AUTHENTICATION FAILURE")

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
		session.SendStringResponse(400, "BAD REQUEST")
	}
}

func challengeDevice(session *sessionState, keytype string, devkey string) (bool, error) {
	// 1) Generate a 32-byte random string of bytes
	// 2) Encode string in base85
	// 3) Encrypt said string, encode in base85, and return it as part of 100 CONTINUE response
	// 4) Wait for response from client and compare response to original base85 string
	// 5) If strings don't match, respond to client with 402 Authentication Failure and return false
	// 6) If strings match respond to client with 200 OK and return true/nil

	randBytes := make([]byte, 32)
	if _, err := rand.Read(randBytes); err != nil {
		panic(err.Error())
	}

	// We Base85-encode the random run of bytes this so that when we receive the response, it
	// should just be a matter of doing a string comparison to determine success
	challenge := b85.Encode(randBytes)
	if keytype != "CURVE25519" {
		return false, errors.New("unsupported key type")
	}

	// Oy, the typing system in Golang can make things... difficult at times. :/
	devkeyDecoded, err := b85.Decode(devkey)

	var devkeyArray [32]byte
	devKeyAdapter := devkeyArray[0:32]
	copy(devKeyAdapter, devkeyDecoded)
	var encryptedChallenge []byte
	encryptedChallenge, err = box.SealAnonymous(nil, []byte(challenge), &devkeyArray, nil)

	var response ServerResponse
	if err != nil {
		response.Code = 300
		response.Status = "INTERNAL SERVER ERROR"
		response.Data["Error"] = err.Error()
		session.SendResponse(response)
		return false, err
	}

	response.Code = 100
	response.Status = "CONTINUE"
	response.Data["Challenge"] = b85.Encode(encryptedChallenge)
	err = session.SendResponse(response)
	if err != nil {
		return false, err
	}

	// Challenge has been issued. Get client response
	request, err := session.GetRequest()
	if err != nil {
		return false, err
	}
	if request.Action != "DEVICE" ||
		request.Validate([]string{"Device-ID", "Device-Key", "Response"}) != nil ||
		request.Data["Device-Key"] != devkey {

		session.SendStringResponse(400, "BAD REQUEST")
		return false, nil
	}

	// Validate client response
	var decodedResponse []byte
	decodedResponse, err = b85.Decode(request.Data["Response"])
	if challenge != string(decodedResponse) {
		return false, nil
	}

	return true, nil
}

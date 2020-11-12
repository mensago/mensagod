package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/darkwyrm/anselusd/dbhandler"
	"github.com/darkwyrm/b85"
	"github.com/spf13/viper"
	"golang.org/x/crypto/nacl/box"
)

func commandDevice(session *sessionState) {
	// Command syntax:
	// DEVICE <devid> <key>

	if len(session.Tokens) != 3 || !dbhandler.ValidateUUID(session.Tokens[1]) ||
		session.LoginState != loginAwaitingSessionID {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	success, err := dbhandler.CheckDevice(session.WID, session.Tokens[1], session.Tokens[2])
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
			// TODO: Check for paranoid mode and reject if enabled
			dbhandler.AddDevice(session.WID, session.Tokens[1], session.Tokens[2], session.Tokens[3],
				"active")

			session.LoginState = loginClientSession
			session.WriteClient("200 OK\r\n")
			return
		}
	} else {
		// The device is part of the workspace already, so now we issue undergo a challenge-response
		// to ensure that the device really is authorized and the key wasn't stolen by an impostor

		success, err = challengeDevice(session, "curve25519", session.Tokens[2])
		if success {
			session.LoginState = loginClientSession
			session.WriteClient("200 OK\r\n")
		} else {
			dbhandler.LogFailure("device", session.WID, session.Connection.RemoteAddr().String())
			session.WriteClient("401 UNAUTHORIZED\r\n")
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
			session.WriteClient(strings.Join([]string{"407 UNAVAILABLE ", lockTime, "\r\n"}, " "))
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
			session.WriteClient(strings.Join([]string{"405 TERMINATED ", lockTime, "\r\n"}, " "))
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
	default:
		session.WriteClient("300 INTERNAL SERVER ERROR\r\n")
	}
}

func commandLogout(session *sessionState) {
	// command syntax:
	// LOGOUT
	session.WriteClient("200 OK\r\n")
	session.IsTerminating = true
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
			session.WriteClient(strings.Join([]string{"405 TERMINATED ", lockTime, "\r\n"}, " "))
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
	if keytype != "curve25519" {
		return false, errors.New("unsupported key type")
	}

	// Oy, the typing system in Golang can make things... difficult at times. :/
	devkeyDecoded, err := b85.Decode(devkey)

	var devkeyArray [32]byte
	devKeyAdapter := devkeyArray[0:32]
	copy(devKeyAdapter, devkeyDecoded)
	var encryptedChallenge []byte
	encryptedChallenge, err = box.SealAnonymous(nil, []byte(challenge), &devkeyArray, nil)
	if err != nil {
		session.WriteClient(fmt.Sprintf("300 INTERNAL SERVER ERROR %s", err))
		return false, err
	}
	session.WriteClient(fmt.Sprintf("100 CONTINUE %s", b85.Encode(encryptedChallenge)))

	// Challenge has been issued. Get client response
	buffer := make([]byte, MaxCommandLength)
	bytesRead, err := session.Connection.Read(buffer)
	if err != nil {
		return false, errors.New("connection timeout")
	}

	pattern := regexp.MustCompile("\"[^\"]+\"|\"[^\"]+$|[\\S\\[\\]]+")
	trimmedString := strings.TrimSpace(string(buffer[:bytesRead]))
	tokens := pattern.FindAllString(trimmedString, -1)
	if len(tokens) != 4 || tokens[0] != "DEVICE" || tokens[2] != devkey {
		return false, nil
	}

	// Validate client response
	var response []byte
	response, err = b85.Decode(tokens[3])
	if challenge != string(response) {
		return false, nil
	}

	return true, nil
}

package main

import (
	"crypto/rand"
	"errors"
	"time"

	"github.com/darkwyrm/anselusd/cryptostring"
	"github.com/darkwyrm/anselusd/dbhandler"
	"github.com/darkwyrm/anselusd/ezcrypt"
	"github.com/darkwyrm/anselusd/logging"
	"github.com/darkwyrm/b85"
	"github.com/spf13/viper"
)

func commandDevice(session *sessionState) {
	// Command syntax:
	// DEVICE(Device-ID,Device-Key)

	session.Message.Validate([]string{"Device-ID", "Device-Key"})
	if !dbhandler.ValidateUUID(session.Message.Data["Device-ID"]) ||
		session.LoginState != loginAwaitingSessionID {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	var devkey cryptostring.CryptoString
	if devkey.Set(session.Message.Data["Device-Key"]) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Bad Device-Key")
		return
	}

	success, err := dbhandler.CheckDevice(session.WID, session.Message.Data["Device-ID"],
		devkey.AsString())
	if err != nil {
		if err.Error() == "cancel" {
			session.LoginState = loginNoSession
			session.SendStringResponse(200, "OK", "")
			return
		}

		session.SendStringResponse(400, "BAD REQUEST", "Bad Device-ID or Device-Key")
		return
	}

	if !success {
		// TODO: implement device checking:
		// 1) Check to see if there are multiple devices
		// 2) If there are multiple devices, push out an authorization message.
		// 3) Record the session ID in the table as a pending device.
		// 4) Return 101 PENDING and close the connection
		// 5) Upon receipt of authorization approval, update the device status in the database
		// 6) Upon receipt of denial, log the failure and apply a lockout to the IP

		// This code exists to at least enable the server to work until device checking can
		// be implemented.
		dbhandler.AddDevice(session.WID, session.Message.Data["Device-ID"], devkey, "active")
	}

	// The device is part of the workspace, so now we issue undergo a challenge-response
	// to ensure that the device really is authorized and the key wasn't stolen by an impostor

	success, err = challengeDevice(session, "CURVE25519", session.Message.Data["Device-Key"])
	if success {
		session.LoginState = loginClientSession
		session.SendStringResponse(200, "OK", "")
	} else {
		dbhandler.LogFailure("device", session.WID, session.Connection.RemoteAddr().String())
		session.SendStringResponse(401, "UNAUTHORIZED", "")
	}
}

func commandLogin(session *sessionState) {
	// Command syntax:
	// LOGIN(Login-Type,Workspace-ID)

	// PLAIN authentication is currently the only supported type
	if session.Message.Validate([]string{"Login-Type", "Workspace-ID", "Challenge"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	if session.Message.Data["Login-Type"] != "PLAIN" {
		session.SendStringResponse(400, "BAD REQUEST", "Invalid login type")
		return
	}

	if !dbhandler.ValidateUUID(session.Message.Data["Workspace-ID"]) {
		session.SendStringResponse(400, "BAD REQUEST", "Invalid Workspace-ID")
		return
	}

	if session.LoginState != loginNoSession {
		session.SendStringResponse(400, "BAD REQUEST", "Session state mismatch")
		return
	}

	wid := session.Message.Data["Workspace-ID"]
	var exists bool
	exists, session.WorkspaceStatus = dbhandler.CheckWorkspace(wid)
	if exists {
		lockTime, err := dbhandler.CheckLockout("workspace", wid, session.Connection.RemoteAddr().String())
		if err != nil {
			session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Writef("commandLogin: error checking lockout: %s", err.Error())
			return
		}

		if len(lockTime) > 0 {
			lockTime, err = dbhandler.CheckLockout("password", wid, session.Connection.RemoteAddr().String())
			if err != nil {
				session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
				logging.Writef("commandLogin: error checking lockout: %s", err.Error())
				return
			}
		}

		if len(lockTime) > 0 {
			// The account is locked if lockTime is greater than 0
			response := NewServerResponse(407, "UNAVAILABLE")
			response.Data["Lock-Time"] = lockTime
			session.SendResponse(*response)
			return
		}

	} else {
		dbhandler.LogFailure("workspace", "", session.Connection.RemoteAddr().String())

		lockTime, err := dbhandler.CheckLockout("workspace", wid, session.Connection.RemoteAddr().String())
		if err != nil {
			session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Writef("commandLogin: error checking lockout: %s", err.Error())
			return
		}

		// If lockTime is non-empty, it means that the client has exceeded the configured threshold.
		// At this point, the connection should be terminated. However, an empty lockTime
		// means that although there has been a failure, the count for this IP address is
		// still under the limit.
		if len(lockTime) > 0 {
			response := NewServerResponse(404, "TERMINATED")
			response.Data["Lock-Time"] = lockTime
			session.SendResponse(*response)
			session.IsTerminating = true
		} else {
			session.SendStringResponse(404, "NOT FOUND", "")
		}
		return
	}

	switch session.WorkspaceStatus {
	case "disabled":
		session.SendStringResponse(411, "ACCOUNT DISABLED", "")
		session.IsTerminating = true
		return
	case "awaiting":
		session.SendStringResponse(101, "PENDING", "")
		session.IsTerminating = true
		return
	case "active", "approved":
		break
	default:
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	// We got this far, so decrypt the challenge and send it to the client
	keypair, err := dbhandler.GetEncryptionPair()
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
	}
	decryptedChallenge, err := keypair.Decrypt(session.Message.Data["Challenge"])
	if err != nil {
		session.SendStringResponse(306, "KEY FAILURE", "Challenge decryption failure")
	}

	session.LoginState = loginAwaitingPassword
	session.WID = wid
	response := NewServerResponse(100, "CONTINUE")
	response.Data["Response"] = string(decryptedChallenge)
	session.SendResponse(*response)
}

func commandLogout(session *sessionState) {
	// command syntax:
	// LOGOUT
	session.SendStringResponse(200, "OK", "")
	session.LoginState = loginNoSession
	session.WID = ""
	session.WorkspaceStatus = ""
}

func commandPassword(session *sessionState) {
	// Command syntax:
	// PASSWORD(Password-Hash)

	// This command takes a numeric hash of the user's password and compares it to what is submitted
	// by the user.
	if !session.Message.HasField("Password-Hash") {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	if session.LoginState != loginAwaitingPassword {
		session.SendStringResponse(400, "BAD REQUEST", "Session state mismatch")
		return
	}

	match, err := dbhandler.CheckPassword(session.WID, session.Message.Data["Password-Hash"])
	if err == nil {
		if match {
			session.LoginState = loginAwaitingSessionID
			session.SendStringResponse(100, "CONTINUE", "")
			return
		}

		dbhandler.LogFailure("password", session.WID, session.Connection.RemoteAddr().String())

		lockTime, err := dbhandler.CheckLockout("password", session.WID,
			session.Connection.RemoteAddr().String())
		if err != nil {
			session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Writef("commandPassword: error checking lockout: %s", err.Error())
			return
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
			session.SendStringResponse(402, "AUTHENTICATION FAILURE", "")

			var d time.Duration
			delayString := viper.GetString("security.failure_delay_sec") + "s"
			d, err = time.ParseDuration(delayString)
			if err != nil {
				logging.Writef("Bad login failure delay string %s. Sleeping 3s.", delayString)
				d, err = time.ParseDuration("3s")
			}
			time.Sleep(d)
		}
	} else {
		session.SendStringResponse(400, "BAD REQUEST", "Password check error")
	}
}

func challengeDevice(session *sessionState, keytype string, devkeystr string) (bool, error) {
	// 1) Generate a 32-byte random string of bytes
	// 2) Encode string in base85
	// 3) Encrypt said string, encode in base85, and return it as part of 100 CONTINUE response
	// 4) Wait for response from client and compare response to original base85 string
	// 5) If strings don't match, respond to client with 402 Authentication Failure and return false
	// 6) If strings match respond to client with 200 OK and return true/nil

	randBytes := make([]byte, 32)
	if _, err := rand.Read(randBytes); err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("challengeDevice: error checking lockout: %s", err.Error())
		return false, err
	}

	// We Base85-encode the random run of bytes this so that when we receive the response, it
	// should just be a matter of doing a string comparison to determine success
	challenge := b85.Encode(randBytes)
	if keytype != "CURVE25519" {
		return false, errors.New("unsupported key type")
	}

	devkey := ezcrypt.NewEncryptionKey(cryptostring.New(devkeystr))
	encryptedChallenge, err := devkey.Encrypt([]byte(challenge))

	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		return false, err
	}

	response := NewServerResponse(100, "CONTINUE")
	response.Data["Challenge"] = encryptedChallenge
	err = session.SendResponse(*response)
	if err != nil {
		return false, err
	}

	// Challenge has been issued. Get client response
	request, err := session.GetRequest()
	if err != nil {
		return false, err
	}
	if request.Action == "CANCEL" {
		return false, errors.New("cancel")
	}

	if request.Action != "DEVICE" {
		session.SendStringResponse(400, "BAD REQUEST", "Session state mismatch")
		return false, nil
	}
	if request.Validate([]string{"Device-ID", "Device-Key", "Response"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return false, nil
	}
	if request.Data["Device-Key"] != devkeystr {
		session.SendStringResponse(400, "BAD REQUEST", "Device key mismatch")
		return false, nil
	}

	// Validate client response
	if challenge != request.Data["Response"] {
		return false, nil
	}

	return true, nil
}

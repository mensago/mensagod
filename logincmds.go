package main

import (
	"crypto/rand"
	"errors"
	"time"

	"github.com/darkwyrm/b85"
	"github.com/darkwyrm/mensagod/cryptostring"
	"github.com/darkwyrm/mensagod/dbhandler"
	"github.com/darkwyrm/mensagod/ezcrypt"
	"github.com/darkwyrm/mensagod/fshandler"
	"github.com/darkwyrm/mensagod/keycard"
	"github.com/darkwyrm/mensagod/logging"
	"github.com/darkwyrm/mensagod/messaging"
	"github.com/everlastingbeta/diceware"
	"github.com/spf13/viper"
)

func commandDevice(session *sessionState) {
	// Command syntax:
	// DEVICE(Device-ID,Device-Key)

	if session.Message.Validate([]string{"Device-ID", "Device-Key"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

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

	success, _ = challengeDevice(session, "CURVE25519", session.Message.Data["Device-Key"])
	if !success {
		lockout, err := logFailure(session, "device", session.WID)
		if err != nil {
			// No need to log here -- logFailure does that.
			session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
			return
		}

		// If locked out, the client has already been notified of the connection termination and
		// all that is left is to exit the command handler
		if !lockout {
			session.SendStringResponse(401, "UNAUTHORIZED", "")
		}
		return
	}

	fsp := fshandler.GetFSProvider()
	exists, err := fsp.Exists("/ " + session.WID)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}
	if !exists {
		fsp.MakeDirectory("/ " + session.WID)
	}
	session.CurrentPath.Set("/ " + session.WID)

	session.LoginState = loginClientSession
	messaging.RegisterWorkspace(session.WID)
	session.LastUpdate = messaging.LastWorkspaceUpdate(session.WID)
	session.SendStringResponse(200, "OK", "")
}

func commandDevKey(session *sessionState) {
	// Command syntax:
	// DEVKEY(Device-ID, Old-Key, New-Key)

	if session.Message.Validate([]string{"Device-ID", "Old-Key", "New-Key"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	var oldkey cryptostring.CryptoString
	if oldkey.Set(session.Message.Data["Old-Key"]) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Bad Old-Key")
		return
	}

	_, err := dbhandler.CheckDevice(session.WID, session.Message.Data["Device-ID"],
		oldkey.AsString())

	if err != nil {
		if err.Error() == "cancel" {
			session.LoginState = loginNoSession
			session.SendStringResponse(200, "OK", "")
			return
		}

		session.SendStringResponse(400, "BAD REQUEST", "Bad Device-ID or Device-Key")
		return
	}

	var newkey cryptostring.CryptoString
	if newkey.Set(session.Message.Data["New-Key"]) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Bad New-Key")
		return
	}

	success, _ := dualChallengeDevice(session, oldkey, newkey)
	if !success {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	err = dbhandler.UpdateDevice(session.WID, session.Message.Data["Device-ID"], oldkey.AsString(),
		newkey.AsString())
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandDevKey: error updating device: %s", err.Error())
		return
	}

	session.SendStringResponse(200, "OK", "")
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
		lockout, err := isLocked(session, "workspace", wid)
		if err != nil || lockout {
			return
		}

		lockout, err = isLocked(session, "password", wid)
		if err != nil || lockout {
			return
		}

	} else {
		terminate, err := logFailure(session, "workspace", "")
		if err != nil || terminate {
			return
		}

		session.SendStringResponse(404, "NOT FOUND", "")
		return
	}

	switch session.WorkspaceStatus {
	case "disabled":
		session.SendStringResponse(407, "UNAVAILABLE", "account disabled")
		return
	case "awaiting":
		session.SendStringResponse(101, "PENDING", "")
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
		return
	}
	decryptedChallenge, err := keypair.Decrypt(session.Message.Data["Challenge"])
	if err != nil {
		session.SendStringResponse(306, "KEY FAILURE", "Challenge decryption failure")
		return
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

func commandPasscode(session *sessionState) {
	// Command syntax:
	// PASSCODE(Workspace-ID, Reset-Code, Password-Hash)

	if session.LoginState != loginNoSession {
		session.SendStringResponse(403, "FORBIDDEN", "Can't reset a password while logged in")
		return
	}

	if session.Message.Validate([]string{"Workspace-ID", "Reset-Code", "Password-Hash"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	if !dbhandler.ValidateUUID(session.Message.Data["Workspace-ID"]) {
		session.SendStringResponse(400, "BAD REQUEST", "bad workspace ID")
		return
	}

	goodPass, err := ezcrypt.IsArgonHash(session.Message.Data["Password-Hash"])
	if !goodPass || err != nil {
		session.SendStringResponse(400, "BAD REQUEST", "bad password hash")
		return
	}

	verified, err := dbhandler.CheckPasscode(session.Message.Data["Workspace-ID"],
		session.Message.Data["Reset-Code"])
	if err != nil {
		if err.Error() == "expired" {
			session.SendStringResponse(415, "EXPIRED", "")
			dbhandler.DeletePasscode(session.Message.Data["Workspace-ID"],
				session.Message.Data["Reset-Code"])
			return
		}

		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandPasscode: Error checking passcode: %s", err.Error())
		return
	}

	if !verified {
		terminate, err := logFailure(session, "passcode", session.Message.Data["Workspace-ID"])
		if terminate || err != nil {
			return
		}
		session.SendStringResponse(402, "AUTHENTICATION FAILURE", "")
		return
	}

	err = dbhandler.SetPassword(session.WID, session.Message.Data["Password-Hash"])
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandPasscode: failed to update password: %s", err.Error())
		return
	}

	session.SendStringResponse(200, "OK", "")
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

	goodPass, err := ezcrypt.IsArgonHash(session.Message.Data["Password-Hash"])
	if !goodPass || err != nil {
		session.SendStringResponse(400, "BAD REQUEST", "bad password hash")
		return
	}

	if session.LoginState != loginAwaitingPassword {
		session.SendStringResponse(400, "BAD REQUEST", "Session state mismatch")
		return
	}

	match, err := dbhandler.CheckPassword(session.WID, session.Message.Data["Password-Hash"])
	if err != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Password check error")
		return
	}

	if !match {
		terminate, err := logFailure(session, "password", session.WID)
		if terminate || err != nil {
			return
		}

		session.SendStringResponse(402, "AUTHENTICATION FAILURE", "")

		var d time.Duration
		delayString := viper.GetString("security.failure_delay_sec") + "s"
		d, err = time.ParseDuration(delayString)
		if err != nil {
			logging.Writef("Bad login failure delay string %s. Sleeping 3s.", delayString)
			d, _ = time.ParseDuration("3s")
		}
		time.Sleep(d)
		return
	}

	session.LoginState = loginAwaitingSessionID
	session.SendStringResponse(100, "CONTINUE", "")
}

func commandResetPassword(session *sessionState) {
	// Command syntax:
	// RESETPASSWORD(Workspace-ID, Reset-Code="", Expires="")

	adminAddress := "admin/" + viper.GetString("global.domain")
	adminWid, err := dbhandler.ResolveAddress(adminAddress)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandResetPassword: Error resolving address: %s", err)
		return
	}

	if session.LoginState != loginClientSession || session.WID != adminWid {
		session.SendStringResponse(403, "FORBIDDEN", "Only admin can use this")
	}

	if !session.Message.HasField("Workspace-ID") {
		session.SendStringResponse(400, "BAD REQUEST", "missing required field")
		return
	}

	if !dbhandler.ValidateUUID(session.Message.Data["Workspace-ID"]) {
		session.SendStringResponse(400, "BAD REQUEST", "Bad Workspace-ID")
		return
	}

	var passcode string
	if session.Message.HasField("Reset-Code") && session.Message.Data["Reset-Code"] != "" {
		if len(session.Message.Data["Reset-Code"]) < 8 {
			session.SendStringResponse(400, "BAD REQUEST",
				"Reset-Code must be at least 8 code points")
			return
		}
		passcode = session.Message.Data["Reset-Code"]
	}
	if passcode == "" {
		passcode, err = diceware.RollWords(viper.GetInt("security.diceware_wordcount"), "-",
			gDiceWordList)
		if err != nil {
			session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Writef("resetpassword: Failed to generate passcode: %s", err.Error())
			return
		}
	}

	var expires string
	if session.Message.HasField("Expires") && session.Message.Data["Expires"] != "" {
		err = keycard.IsExpirationValid(session.Message.Data["Expires"])
		if err != nil {
			session.SendStringResponse(400, "BAD REQUEST", "Bad Expires field")
			return
		}
		expires = session.Message.Data["Expires"]
	}
	if expires == "" {
		expires = time.Now().UTC().
			Add(time.Minute * time.Duration(viper.GetInt("security.password_reset_min"))).
			Format("20060102T150405Z")
	}

	err = dbhandler.ResetPassword(session.Message.Data["Workspace-ID"], passcode, expires)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandResetPassword: failed to add password reset code: %s", err.Error())
		return
	}

	response := NewServerResponse(200, "OK")
	response.Data["Reset-Code"] = passcode
	response.Data["Expires"] = expires
	session.SendResponse(*response)
}

func commandSetPassword(session *sessionState) {
	// Command syntax:
	// SETPASSWORD(Password-Hash, NewPassword-Hash)

	if session.Message.Validate([]string{"Password-Hash", "NewPassword-Hash"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	goodPass, err := ezcrypt.IsArgonHash(session.Message.Data["Password-Hash"])
	if !goodPass || err != nil {
		session.SendStringResponse(400, "BAD REQUEST", "bad old password hash")
		return
	}

	goodPass, err = ezcrypt.IsArgonHash(session.Message.Data["NewPassword-Hash"])
	if !goodPass || err != nil {
		session.SendStringResponse(400, "BAD REQUEST", "bad new password hash")
		return
	}

	match, err := dbhandler.CheckPassword(session.WID, session.Message.Data["Password-Hash"])
	if err != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Password check error")
		return
	}

	if !match {
		session.SendStringResponse(402, "AUTHENTICATION FAILURE", "")
		return
	}

	err = dbhandler.SetPassword(session.WID, session.Message.Data["NewPassword-Hash"])
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandSetPassword: failed to update password: %s", err.Error())
		return
	}

	session.SendStringResponse(200, "OK", "")
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

func dualChallengeDevice(session *sessionState, oldkey cryptostring.CryptoString,
	newkey cryptostring.CryptoString) (bool, error) {
	// This is just like challengeDevice, but using two keys, an old one and a new one

	if oldkey.Prefix != "CURVE25519" || newkey.Prefix != "CURVE25519" {
		return false, errors.New("unsupported key type")
	}

	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("challengeDevice: error checking lockout: %s", err.Error())
		return false, err
	}
	challenge := b85.Encode(randBytes)

	encryptor := ezcrypt.NewEncryptionKey(oldkey)
	encryptedChallenge, err := encryptor.Encrypt([]byte(challenge))

	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		return false, err
	}

	response := NewServerResponse(100, "CONTINUE")
	response.Data["Challenge"] = encryptedChallenge

	_, err = rand.Read(randBytes)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("challengeDevice: error checking lockout: %s", err.Error())
		return false, err
	}
	newChallenge := b85.Encode(randBytes)

	encryptor = ezcrypt.NewEncryptionKey(newkey)
	encryptedNewChallenge, err := encryptor.Encrypt([]byte(newChallenge))

	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		return false, err
	}
	response.Data["New-Challenge"] = encryptedNewChallenge

	err = session.SendResponse(*response)
	if err != nil {
		return false, err
	}

	// Challenges have been issued. Get client responses
	request, err := session.GetRequest()
	if err != nil {
		return false, err
	}
	if request.Action == "CANCEL" {
		return false, errors.New("cancel")
	}

	if request.Action != "DEVKEY" {
		session.SendStringResponse(400, "BAD REQUEST", "Session state mismatch")
		return false, nil
	}
	if request.Validate([]string{"Response", "New-Response"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return false, nil
	}

	// Validate client response
	if challenge != request.Data["Response"] || newChallenge != request.Data["New-Response"] {
		return false, nil
	}

	return true, nil
}

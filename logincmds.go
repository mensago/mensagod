package main

import (
	"crypto/rand"
	"time"

	"github.com/everlastingbeta/diceware"
	"github.com/spf13/viper"
	"gitlab.com/darkwyrm/b85"
	ezn "gitlab.com/darkwyrm/goeznacl"
	"gitlab.com/mensago/mensagod/dbhandler"
	"gitlab.com/mensago/mensagod/fshandler"
	"gitlab.com/mensago/mensagod/keycard"
	"gitlab.com/mensago/mensagod/logging"
	"gitlab.com/mensago/mensagod/messaging"
	"gitlab.com/mensago/mensagod/misc"
	"gitlab.com/mensago/mensagod/types"
)

func commandDevice(session *sessionState) {
	// Command syntax:
	// DEVICE(Device-ID,Device-Key)

	if session.Message.Validate([]string{"Device-ID", "Device-Key"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	devid := types.ToUUID(session.Message.Data["Device-ID"])
	if !devid.IsValid() ||
		session.LoginState != loginAwaitingSessionID {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad device ID")
		return
	}

	var devkey ezn.CryptoString
	if devkey.Set(session.Message.Data["Device-Key"]) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad Device-Key")
		return
	}

	success, err := dbhandler.CheckDevice(session.WID, devid, devkey)
	if err != nil {
		if err.Error() == "cancel" {
			session.LoginState = loginNoSession
			session.SendQuickResponse(200, "OK", "")
			return
		}

		session.SendQuickResponse(400, "BAD REQUEST", "Bad Device-ID or Device-Key")
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
		dbhandler.AddDevice(session.WID, devid, devkey, "active")
	}

	// The device is part of the workspace, so now we issue undergo a challenge-response
	// to ensure that the device really is authorized and the key wasn't stolen by an impostor

	success, _ = challengeDevice(session, "CURVE25519", devkey.AsString())
	if !success {
		lockout, err := logFailure(session, "device", session.WID)
		if err != nil {
			// No need to log here -- logFailure does that.
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			return
		}

		// If locked out, the client has already been notified of the connection termination and
		// all that is left is to exit the command handler
		if !lockout {
			session.SendQuickResponse(401, "UNAUTHORIZED", "")
		}
		return
	}

	fsp := fshandler.GetFSProvider()
	exists, err := fsp.Exists("/ wsp " + session.WID.AsString())
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}
	if !exists {
		fsp.MakeDirectory("/ wsp " + session.WID.AsString())
	}
	session.CurrentPath.Set("/ wsp " + session.WID.AsString())

	session.LoginState = loginClientSession

	messaging.RegisterWorkspace(session.WID.AsString())
	lastLogin, err := dbhandler.GetLastLogin(session.WID, devid)
	if err != nil {
		logging.Writef("commandDevice: error getting last login for %s:%s: %s", session.WID.AsString(),
			session.Message.Data["Device-ID"], err.Error())
		lastLogin = -1
	}
	session.LastUpdateSent = lastLogin

	response := NewServerResponse(200, "OK")

	isAdmin, err := session.IsAdmin()
	if err != nil {
		return
	}
	if isAdmin {
		response.Data["Is-Admin"] = "True"
	} else {
		response.Data["Is-Admin"] = "False"
	}
	session.SendResponse(*response)

	err = dbhandler.UpdateLastLogin(session.WID, devid)
	if err != nil {
		logging.Writef("commandDevice: error setting last login for %s:%s: %s", session.WID.AsString(),
			session.Message.Data["Device-ID"], err.Error())
	}
}

func commandDevKey(session *sessionState) {
	// Command syntax:
	// DEVKEY(Device-ID, Old-Key, New-Key)

	if !session.RequireLogin() {
		return
	}

	if session.Message.Validate([]string{"Device-ID", "Old-Key", "New-Key"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	var oldkey ezn.CryptoString
	if oldkey.Set(session.Message.Data["Old-Key"]) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad Old-Key")
		return
	}

	devid := types.ToUUID(session.Message.Data["Device-ID"])
	if !devid.IsValid() {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad device ID")
		return
	}
	_, err := dbhandler.CheckDevice(session.WID, devid, oldkey)

	if err != nil {
		if err.Error() == "cancel" {
			session.LoginState = loginNoSession
			session.SendQuickResponse(200, "OK", "")
			return
		}

		session.SendQuickResponse(400, "BAD REQUEST", "Bad device ID or device key")
		return
	}

	var newkey ezn.CryptoString
	if newkey.Set(session.Message.Data["New-Key"]) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad New-Key")
		return
	}

	success, _ := dualChallengeDevice(session, oldkey, newkey)
	if !success {
		session.SendQuickResponse(401, "UNAUTHORIZED", "")
		return
	}

	err = dbhandler.UpdateDevice(session.WID, devid, oldkey, newkey)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "DevKey.1")
		logging.Writef("commandDevKey: error updating device: %s", err.Error())
		return
	}

	session.SendQuickResponse(200, "OK", "")
}

func commandLogin(session *sessionState) {
	// Command syntax:
	// LOGIN(Login-Type,Workspace-ID)

	// PLAIN authentication is currently the only supported type
	if session.Message.Validate([]string{"Login-Type", "Workspace-ID", "Challenge"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	if session.Message.Data["Login-Type"] != "PLAIN" {
		session.SendQuickResponse(400, "BAD REQUEST", "Invalid login type")
		return
	}

	wid := types.ToUUID(session.Message.Data["Workspace-ID"])
	if !wid.IsValid() {
		session.SendQuickResponse(400, "BAD REQUEST", "Invalid workspace ID")
		return
	}

	if session.LoginState != loginNoSession {
		session.SendQuickResponse(400, "BAD REQUEST", "Session state mismatch")
		return
	}

	var exists bool
	exists, session.WorkspaceStatus = dbhandler.CheckWorkspace(wid.AsString())

	if !exists {
		terminate, err := logFailure(session, "workspace", "")
		if err != nil || terminate {
			return
		}

		session.SendQuickResponse(404, "NOT FOUND", "")
		return
	}

	switch session.WorkspaceStatus {
	case "active", "approved":
		// This is fine. Everything is fine. 😉
		break
	case "awaiting":
		session.SendQuickResponse(101, "PENDING", "Registration awaiting administrator approval")
		return
	case "deleted":
		session.SendQuickResponse(404, "NOT FOUND", "")
		return
	case "disabled":
		session.SendQuickResponse(407, "UNAVAILABLE", "account disabled")
		return
	case "suspended":
		session.SendQuickResponse(407, "UNAVAILABLE", "account suspended")
		return
	case "unpaid":
		session.SendQuickResponse(406, "PAYMENT REQUIRED", "")
		return
	default:
		logging.Writef("Unrecognized workspace status '%s' during login", session.WorkspaceStatus)
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR",
			"Unrecognized status for workspace")
		return
	}

	lockout, err := isLocked(session, "workspace", wid)
	if err != nil || lockout {
		return
	}

	lockout, err = isLocked(session, "password", wid)
	if err != nil || lockout {
		return
	}

	// The challenge is expected to be in CryptoString format in order to be able to ensure the
	// algorithm used by the client matches the org's key
	challengeCS := ezn.NewCS(session.Message.Data["Challenge"])

	// We got this far, so decrypt the challenge and send it to the client
	keypair, err := dbhandler.GetEncryptionPair()
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	decryptedChallenge, err := keypair.Decrypt(challengeCS.Data)
	if err != nil {
		session.SendQuickResponse(306, "KEY FAILURE", "Challenge decryption failure")
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
	session.SendQuickResponse(200, "OK", "")
	session.LoginState = loginNoSession
	session.WID.Set("")
	session.WorkspaceStatus = ""
}

func commandPasscode(session *sessionState) {
	// Command syntax:
	// PASSCODE(Workspace-ID, Reset-Code, Password-Hash)

	if session.LoginState != loginNoSession {
		session.SendQuickResponse(403, "FORBIDDEN", "Can't reset a password while logged in")
		return
	}

	if session.Message.Validate([]string{"Workspace-ID", "Reset-Code", "Password-Hash"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	wid := types.ToUUID(session.Message.Data["Workspace-ID"])
	if !wid.IsValid() {
		session.SendQuickResponse(400, "BAD REQUEST", "bad workspace ID")
		return
	}

	goodPass, err := ezn.IsArgonHash(session.Message.Data["Password-Hash"])
	if !goodPass || err != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "bad password hash")
		return
	}

	verified, err := dbhandler.CheckPasscode(wid, session.Message.Data["Reset-Code"])
	if err != nil {
		if err.Error() == "expired" {
			session.SendQuickResponse(415, "EXPIRED", "")
			dbhandler.DeletePasscode(wid, session.Message.Data["Reset-Code"])
			return
		}

		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandPasscode: Error checking passcode: %s", err.Error())
		return
	}

	if !verified {
		terminate, err := logFailure(session, "passcode", wid)
		if terminate || err != nil {
			return
		}
		session.SendQuickResponse(402, "AUTHENTICATION FAILURE", "")
		return
	}

	err = dbhandler.SetPassword(session.WID, session.Message.Data["Password-Hash"])
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandPasscode: failed to update password: %s", err.Error())
		return
	}

	session.SendQuickResponse(200, "OK", "")
}

func commandPassword(session *sessionState) {
	// Command syntax:
	// PASSWORD(Password-Hash)

	// This command takes a numeric hash of the user's password and compares it to what is submitted
	// by the user.
	if !session.Message.HasField("Password-Hash") {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	goodPass, err := ezn.IsArgonHash(session.Message.Data["Password-Hash"])
	if !goodPass || err != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "bad password hash")
		return
	}

	if session.LoginState != loginAwaitingPassword {
		session.SendQuickResponse(400, "BAD REQUEST", "Session state mismatch")
		return
	}

	match, err := dbhandler.CheckPassword(session.WID, session.Message.Data["Password-Hash"])
	if err != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Password check error")
		return
	}

	if !match {
		terminate, err := logFailure(session, "password", session.WID)
		if terminate || err != nil {
			return
		}

		session.SendQuickResponse(402, "AUTHENTICATION FAILURE", "")

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
	session.SendQuickResponse(100, "CONTINUE", "")
}

func commandResetPassword(session *sessionState) {
	// Command syntax:
	// RESETPASSWORD(Workspace-ID, Reset-Code="", Expires="")

	if isAdmin, err := session.RequireAdmin(); err != nil || !isAdmin {
		return
	}

	if !session.Message.HasField("Workspace-ID") {
		session.SendQuickResponse(400, "BAD REQUEST", "missing required field")
		return
	}

	wid := types.ToUUID(session.Message.Data["Workspace-ID"])
	if !wid.IsValid() {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad workspace id")
		return
	}

	var passcode string
	if session.Message.HasField("Reset-Code") && session.Message.Data["Reset-Code"] != "" {
		if len(session.Message.Data["Reset-Code"]) < 8 {
			session.SendQuickResponse(400, "BAD REQUEST",
				"Reset-Code must be at least 8 code points")
			return
		}
		passcode = session.Message.Data["Reset-Code"]
	}

	var err error
	if passcode == "" {
		passcode, err = diceware.RollWords(viper.GetInt("security.diceware_wordcount"), "-",
			gDiceWordList)
		if err != nil {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Writef("resetpassword: Failed to generate passcode: %s", err.Error())
			return
		}
	}

	var expires string
	if session.Message.HasField("Expires") && session.Message.Data["Expires"] != "" {
		err = keycard.IsExpirationValid(session.Message.Data["Expires"])
		if err != nil {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad Expires field")
			return
		}
		expires = session.Message.Data["Expires"]
	}
	if expires == "" {
		expires = time.Now().UTC().
			Add(time.Minute * time.Duration(viper.GetInt("security.password_reset_min"))).
			Format("20060102T150405Z")
	}

	err = dbhandler.ResetPassword(wid, passcode, expires)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
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

	if !session.RequireLogin() {
		return
	}

	if session.Message.Validate([]string{"Password-Hash", "NewPassword-Hash"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	if len(session.Message.Data["Password-Hash"]) < 16 ||
		len(session.Message.Data["NewPassword-Hash"]) < 16 {

		session.SendQuickResponse(400, "BAD REQUEST", "password hashes must be at least 128 bits")
		return
	}

	if session.Message.Data["Password-Hash"] == session.Message.Data["NewPassword-Hash"] {

		session.SendQuickResponse(400, "BAD REQUEST", "password hashes must not be the same")
		return
	}

	goodPass, err := ezn.IsArgonHash(session.Message.Data["Password-Hash"])
	if !goodPass || err != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "bad old password hash")
		return
	}

	goodPass, err = ezn.IsArgonHash(session.Message.Data["NewPassword-Hash"])
	if !goodPass || err != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "bad new password hash")
		return
	}

	match, err := dbhandler.CheckPassword(session.WID, session.Message.Data["Password-Hash"])
	if err != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Password check error")
		return
	}

	if !match {
		session.SendQuickResponse(402, "AUTHENTICATION FAILURE", "")
		return
	}

	err = dbhandler.SetPassword(session.WID, session.Message.Data["NewPassword-Hash"])
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandSetPassword: failed to update password: %s", err.Error())
		return
	}

	session.SendQuickResponse(200, "OK", "")
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
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("challengeDevice: error checking lockout: %s", err.Error())
		return false, err
	}

	// We Base85-encode the random run of bytes this so that when we receive the response, it
	// should just be a matter of doing a string comparison to determine success
	challenge := b85.Encode(randBytes)
	if keytype != "CURVE25519" {
		return false, ezn.ErrUnsupportedAlgorithm
	}

	devkey := ezn.NewEncryptionKey(ezn.NewCS(devkeystr))
	encryptedChallenge, err := devkey.Encrypt([]byte(challenge))

	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return false, err
	}

	response := NewServerResponse(100, "CONTINUE")
	response.Data["Challenge"] = keytype + ":" + encryptedChallenge
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
		return false, misc.ErrCanceled
	}

	if request.Action != "DEVICE" {
		session.SendQuickResponse(400, "BAD REQUEST", "Session state mismatch")
		return false, nil
	}
	if request.Validate([]string{"Device-ID", "Device-Key", "Response"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return false, nil
	}
	if request.Data["Device-Key"] != devkeystr {
		session.SendQuickResponse(400, "BAD REQUEST", "Device key mismatch")
		return false, nil
	}

	// Validate client response
	if challenge != request.Data["Response"] {
		return false, nil
	}

	return true, nil
}

func dualChallengeDevice(session *sessionState, oldkey ezn.CryptoString,
	newkey ezn.CryptoString) (bool, error) {
	// This is much like challengeDevice, but using two keys, an old one and a new one
	// - receive 2 keys
	// - send 2 challenges
	// - receive and verify 2 responses
	// - update device key

	// TODO: utilize goeznacl::IsSupportedAlgorithm()

	if oldkey.Prefix != "CURVE25519" || newkey.Prefix != "CURVE25519" {
		return false, ezn.ErrUnsupportedAlgorithm
	}

	// Create old key challenge

	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("challengeDevice: error checking lockout: %s", err.Error())
		return false, err
	}
	oldChallenge := b85.Encode(randBytes)

	encryptor := ezn.NewEncryptionKey(oldkey)
	oldEncChallenge, err := encryptor.Encrypt([]byte(oldChallenge))
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return false, err
	}

	// Create new key challenge

	randBytes = make([]byte, 32)
	_, err = rand.Read(randBytes)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("challengeDevice: error checking lockout: %s", err.Error())
		return false, err
	}
	newChallenge := b85.Encode(randBytes)

	encryptor = ezn.NewEncryptionKey(newkey)
	newEncChallenge, err := encryptor.Encrypt([]byte(newChallenge))
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return false, err
	}

	response := NewServerResponse(100, "CONTINUE")
	response.Data["Challenge"] = oldkey.Prefix + ":" + oldEncChallenge
	response.Data["New-Challenge"] = newkey.Prefix + ":" + newEncChallenge

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
		return false, misc.ErrCanceled
	}

	if request.Action != "DEVKEY" {
		session.SendQuickResponse(400, "BAD REQUEST", "Session state mismatch")
		return false, nil
	}
	if request.Validate([]string{"Response", "New-Response"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return false, nil
	}

	// Validate client response
	if oldChallenge != request.Data["Response"] || newChallenge != request.Data["New-Response"] {
		return false, nil
	}

	return true, nil
}

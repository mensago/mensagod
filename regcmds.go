package main

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/darkwyrm/mensagod/cryptostring"
	"github.com/darkwyrm/mensagod/dbhandler"
	"github.com/darkwyrm/mensagod/ezcrypt"
	"github.com/darkwyrm/mensagod/fshandler"
	"github.com/darkwyrm/mensagod/logging"
	"github.com/google/uuid"
	"github.com/spf13/viper"
)

func commandGetWID(session *sessionState) {
	// command syntax:
	// GETWID(User-ID, Domain="")
	if !session.Message.HasField("User-ID") {
		session.SendStringResponse(400, "BAD REQUEST", "")
		return
	}

	if strings.ContainsAny(session.Message.Data["User-ID"], "/\"") {
		session.SendStringResponse(400, "BAD REQUEST", "Bad User-ID")
		return
	}

	var domain string
	if session.Message.HasField("Domain") {
		domain = session.Message.Data["Domain"]
		pattern := regexp.MustCompile("([a-zA-Z0-9]+\x2E)+[a-zA-Z0-9]+")
		if !pattern.MatchString(domain) {
			session.SendStringResponse(400, "BAD REQUEST", "Bad Domain")
			return
		}
	} else {
		domain = viper.GetString("global.domain")
	}

	lockout, err := isLocked(session, "widlookup", "")
	if lockout || err != nil {
		return
	}

	address := strings.Join([]string{session.Message.Data["User-ID"], "/", domain}, "")
	wid, err := dbhandler.ResolveAddress(address)
	if err != nil {
		if err.Error() == "workspace not found" {
			terminate, err := logFailure(session, "widlookup", "")
			if terminate || err != nil {
				return
			}
		}
	}
	response := NewServerResponse(200, "OK")
	response.Data["Workspace-ID"] = wid
	session.SendResponse(*response)
}

func commandPreregister(session *sessionState) {
	// command syntax:
	// PREREG(User-ID="",Workspace-ID="",Domain="")

	adminAddress := "admin/" + viper.GetString("global.domain")
	adminWid, err := dbhandler.ResolveAddress(adminAddress)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandPreregister: Error resolving address: %s", err)
		return
	}

	if session.LoginState != loginClientSession || session.WID != adminWid {
		session.SendStringResponse(403, "FORBIDDEN", "Only admin can use this")
		return
	}

	// Just do some basic syntax checks on the user ID
	uid := ""
	if session.Message.HasField("User-ID") {
		uid = session.Message.Data["User-ID"]
		if strings.ContainsAny(uid, "/\"") {
			session.SendStringResponse(400, "BAD REQUEST", "Bad User-ID")
			return
		}

		success, _ := dbhandler.CheckUserID(session.Message.Data["User-ID"])
		if success {
			session.SendStringResponse(408, "RESOURCE EXISTS", "User-ID exists")
			return
		}
	}

	// If the client submits a workspace ID as the user ID, it is considered a request for that
	// specific workspace ID and the user ID is considered blank.
	wid := ""
	if dbhandler.ValidateUUID(uid) {
		wid = uid
		uid = ""
	} else if session.Message.HasField("Workspace-ID") {
		wid = session.Message.Data["Workspace-ID"]
		if !dbhandler.ValidateUUID(wid) {
			session.SendStringResponse(400, "BAD REQUEST", "Bad Workspace-ID")
			return
		}
	}

	domain := ""
	if session.Message.HasField("Domain") {
		domain = session.Message.Data["Domain"]
		pattern := regexp.MustCompile("([a-zA-Z0-9]+\x2E)+[a-zA-Z0-9]+")
		if !pattern.MatchString(domain) {
			session.SendStringResponse(400, "BAD REQUEST", "Bad Domain")
			return
		}
	}
	if domain == "" {
		domain = viper.GetString("global.domain")
	}

	var haswid bool
	if wid != "" {
		haswid, _ = dbhandler.CheckWorkspace(wid)
		if haswid {
			session.SendStringResponse(408, "RESOURCE EXISTS", "")
			return
		}
	} else {
		haswid = true
		for haswid {
			wid = uuid.New().String()
			haswid, _ = dbhandler.CheckWorkspace(wid)
		}
	}

	regcode, err := dbhandler.PreregWorkspace(wid, uid, domain, &gDiceWordList,
		viper.GetInt("security.diceware_wordcount"))
	if err != nil {
		if err.Error() == "uid exists" {
			session.SendStringResponse(408, "RESOURCE EXISTS", "")
			return
		}
		logging.Write(fmt.Sprintf("Internal server error. commandPreregister.PreregWorkspace. "+
			"Error: %s\n", err))
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	fsp := fshandler.GetFSProvider()
	exists, err := fsp.Exists("/ " + wid)
	if err != nil {
		logging.Writef("commandPreregister: Failed to check workspace %s existence: %s",
			wid, err)
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}
	if !exists {
		fsp.MakeDirectory("/ " + wid)
		if err != nil {
			logging.Writef("commandPreregister: Failed to create workspace %s top directory: %s",
				wid, err)
			session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
			return
		}
	}

	response := NewServerResponse(200, "OK")
	if uid != "" {
		response.Data["User-ID"] = uid
	}
	response.Data["Workspace-ID"] = wid
	response.Data["Domain"] = domain
	response.Data["Reg-Code"] = regcode
	session.SendResponse(*response)
}

func commandRegCode(session *sessionState) {
	// command syntax:
	// REGCODE(User-ID, Reg-Code, Password-Hash, Device-ID, Device-Key, Domain="")
	// REGCODE(Workspace-ID, Reg-Code, Password-Hash, Device-ID, Device-Key, Domain="")

	if session.Message.Validate([]string{"Reg-Code", "Password-Hash", "Device-ID",
		"Device-Key"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}
	if !dbhandler.ValidateUUID(session.Message.Data["Device-ID"]) {
		session.SendStringResponse(400, "BAD REQUEST", "Invalid Device-ID")
		return
	}

	if len(session.Message.Data["Reg-Code"]) > 128 {
		session.SendStringResponse(400, "BAD REQUEST", "Invalid reg code")
		return
	}

	// The password field is expected to contain an Argon2id password hash
	isArgon, err := ezcrypt.IsArgonHash(session.Message.Data["Password-Hash"])
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandRegCode: error check password hash: %s", err)
		return
	}

	if !isArgon {
		session.SendStringResponse(400, "BAD REQUEST", "Invalid password hash")
		return
	}

	if !dbhandler.ValidateUUID(session.Message.Data["Device-ID"]) {
		session.SendStringResponse(400, "BAD REQUEST", "Bad device ID")
		return
	}
	// check to see if this is a workspace ID

	if session.Message.HasField("User-ID") {
		if strings.ContainsAny(session.Message.Data["User-ID"], "/\"") {
			session.SendStringResponse(400, "BAD REQUEST", "Invalid User-ID")
			return
		}
	} else if session.Message.HasField("Workspace-ID") {
		if !dbhandler.ValidateUUID(session.Message.Data["Workspace-ID"]) {
			session.SendStringResponse(400, "BAD REQUEST", "Invalid Workspace-ID")
			return
		}
	} else {
		session.SendStringResponse(400, "BAD REQUEST", "")
		return
	}

	domain := ""
	if session.Message.HasField("Domain") {
		domain = session.Message.Data["Domain"]
		pattern := regexp.MustCompile("([a-zA-Z0-9]+\x2E)+[a-zA-Z0-9]+")
		if !pattern.MatchString(domain) {
			session.SendStringResponse(400, "BAD REQUEST", "Bad Domain")
			return
		}
	}
	if domain == "" {
		domain = viper.GetString("global.domain")
	}

	// If lockTime is non-empty, it means that the client has exceeded the configured threshold.
	// At this point, the connection should be terminated. However, an empty lockTime
	// means that although there has been a failure, the count for this IP address is
	// still under the limit.
	lockout, err := isLocked(session, "prereg", "")
	if lockout || err != nil {
		return
	}

	var devkey cryptostring.CryptoString
	if devkey.Set(session.Message.Data["Device-Key"]) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Bad Device-Key")
		return
	}

	if devkey.Prefix != "CURVE25519" {
		session.SendStringResponse(309, "ENCRYPTION TYPE NOT SUPPORTED", "Supported: CURVE25519")
		return
	}

	var wid, uid string
	if session.Message.HasField("Workspace-ID") {
		wid, uid, err = dbhandler.CheckRegCode(session.Message.Data["Workspace-ID"], domain, true,
			session.Message.Data["Reg-Code"])
	} else {
		wid, uid, err = dbhandler.CheckRegCode(session.Message.Data["User-ID"], domain, false,
			session.Message.Data["Reg-Code"])
	}

	if wid == "" {
		// Regardless of whether or not an error has been returned from log, we exit here. In this
		// case, state doesn't matter.
		logFailure(session, "prereg", "")
		return
	}

	err = dbhandler.AddWorkspace(wid, uid, domain, session.Message.Data["Password-Hash"], "active",
		"individual")
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("Internal server error. commandRegister.AddWorkspace. Error: %s\n", err)
		return
	}

	err = dbhandler.SetWorkspaceStatus(wid, "active")
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("Internal server error. commandRegister.SetWorkspaceStatus. Error: %s\n", err)
		return
	}

	err = dbhandler.AddDevice(wid, session.Message.Data["Device-ID"], devkey, "active")
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("Internal server error. commandRegister.AddDevice. Error: %s\n", err)
		return
	}

	if session.Message.HasField("Workspace-ID") {
		err = dbhandler.DeleteRegCode(session.Message.Data["Workspace-ID"], domain, true,
			session.Message.Data["Reg-Code"])
	} else {
		err = dbhandler.DeleteRegCode(session.Message.Data["User-ID"], domain, false,
			session.Message.Data["Reg-Code"])
	}
	if err != nil {
		logging.Writef("Internal server error. commandRegister.DeleteRegCode. Error: %s\n", err)
		return
	}

	session.SendStringResponse(201, "REGISTERED", "")
}

func commandRegister(session *sessionState) {
	// command syntax:
	// REGISTER(Workspace-ID, Password-Hash, Device-ID, Device-Key, User-ID="", Type="")

	if session.Message.Validate([]string{"Workspace-ID", "Password-Hash", "Device-ID",
		"Device-Key"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}
	if !dbhandler.ValidateUUID(session.Message.Data["Workspace-ID"]) {
		session.SendStringResponse(400, "BAD REQUEST", "Invalid Workspace-ID")
		return
	}

	// Just do some basic syntax checks on the user ID
	uid := ""
	if session.Message.HasField("User-ID") {
		uid = session.Message.Data["User-ID"]
		if strings.ContainsAny(uid, "/\"") {
			session.SendStringResponse(400, "BAD REQUEST", "Bad User-ID")
			return
		}
	}

	wtype := "individual"
	if session.Message.HasField("Type") {
		wtype = session.Message.Data["Type"]
		if wtype != "shared" && wtype != "individual" {
			session.SendStringResponse(400, "BAD REQUEST", "Bad Type")
			return
		}

		// TODO: Eliminate this when shared workspaces are implemented
		if wtype == "shared" {
			session.SendStringResponse(301, "NOT IMPLEMENTED", "")
			return
		}
	}
	regType := strings.ToLower(viper.GetString("global.registration"))

	if regType == "private" {
		session.SendStringResponse(304, "REGISTRATION CLOSED", "")
		return
	}

	success, _ := dbhandler.CheckWorkspace(session.Message.Data["Workspace-ID"])
	if success {
		response := NewServerResponse(408, "RESOURCE EXISTS")
		response.Data["Field"] = "Workspace-ID"
		session.SendResponse(*response)
		return
	}

	if session.Message.HasField("User-ID") {
		success, _ = dbhandler.CheckUserID(session.Message.Data["User-ID"])
		if success {
			response := NewServerResponse(408, "RESOURCE EXISTS")
			response.Data["Field"] = "User-ID"
			session.SendResponse(*response)
			return
		}
	}

	// TODO: Check number of recent registration requests from this IP

	var workspaceStatus string
	switch regType {
	case "network":

		ipParts := strings.Split(session.Connection.RemoteAddr().String(), ":")
		clientIP := net.ParseIP(ipParts[0])

		parts := strings.Split(viper.GetString("global.registration_subnet"), ",")
		clientInSubnet := false
		for _, part := range parts {
			netstring := strings.TrimSpace(part)

			// Skipping the error checking on the subnet strings because it's done during startup
			_, subnet, _ := net.ParseCIDR(netstring)
			if subnet.Contains(clientIP) {
				clientInSubnet = true
				break
			}
		}
		if !clientInSubnet {
			session.SendStringResponse(304, "REGISTRATION CLOSED", "")
			return
		}
		workspaceStatus = "active"
	case "moderated":
		workspaceStatus = "pending"
	default:
		workspaceStatus = "active"
	}

	var devkey cryptostring.CryptoString
	if devkey.Set(session.Message.Data["Device-Key"]) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Bad Device-Key")
		return
	}

	if devkey.Prefix != "CURVE25519" {
		session.SendStringResponse(309, "ENCRYPTION TYPE NOT SUPPORTED", "Supported: CURVE25519")
		return
	}

	err := dbhandler.AddWorkspace(session.Message.Data["Workspace-ID"], uid,
		viper.GetString("global.domain"), session.Message.Data["Password-Hash"], workspaceStatus,
		wtype)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("Internal server error. commandRegister.AddWorkspace. Error: %s\n", err)
		return
	}

	devid := uuid.New().String()
	err = dbhandler.AddDevice(session.Message.Data["Workspace-ID"], devid, devkey, "active")
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("Internal server error. commandRegister.AddDevice. Error: %s\n", err)
		return
	}

	fsp := fshandler.GetFSProvider()
	exists, err := fsp.Exists("/ " + session.Message.Data["Workspace-ID"])
	if err != nil {
		logging.Writef("commandPreregister: Failed to check workspace %s existence: %s",
			session.Message.Data["Workspace-ID"], err)
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}
	if !exists {
		fsp.MakeDirectory("/ " + session.Message.Data["Workspace-ID"])
		if err != nil {
			logging.Writef("commandPreregister: Failed to create workspace %s top directory: %s",
				session.Message.Data["Workspace-ID"], err)
			session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
			return
		}
	}

	if regType == "moderated" {
		session.SendStringResponse(101, "PENDING", "")
	} else {
		response := NewServerResponse(201, "REGISTERED")
		response.Data["Domain"] = viper.GetString("global.domain")
		session.SendResponse(*response)
	}
}

func commandUnrecognized(session *sessionState) {
	// command used when not recognized
	session.SendStringResponse(400, "BAD REQUEST", "Unrecognized command")
}

func commandUnregister(session *sessionState) {
	// command syntax:
	// UNREGISTER(Password-Hash)
	if !session.Message.HasField("Password-Hash") {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "Must be logged in for this command")
	}

	match, err := dbhandler.CheckPassword(session.WID, session.Message.Data["Password-Hash"])
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("Unregister: error checking password: %s", err.Error())
		return
	}
	if !match {
		session.SendStringResponse(401, "UNAUTHORIZED", "Password mismatch")
		return
	}

	regType := strings.ToLower(viper.GetString("global.registration"))
	if regType == "private" || regType == "moderated" {
		// TODO: submit admin request to delete workspace
		// session.SendStringResponse(101, "PENDING", "Pending administrator approval")
		session.SendStringResponse(301, "NOT IMPLEMENTED", "Not implemented yet. Sorry!")
		return
	}

	adminWid, err := dbhandler.ResolveAddress("admin/" + viper.GetString("global.domain"))
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Write("Unregister: failed to resolve admin account")
		return
	}

	// This command can be used to unregister other workspaces, but only the admin account is
	// allowed to do this
	wid := session.WID
	if session.Message.HasField("Workspace-ID") {
		if !dbhandler.ValidateUUID(session.Message.Data["Workspace-ID"]) {
			session.SendStringResponse(400, "BAD REQUEST", "Bad Workspace-ID")
			return
		}

		if session.WID != session.Message.Data["Workspace-ID"] {

			if session.WID != adminWid {
				session.SendStringResponse(401, "UNAUTHORIZED",
					"Only admin can unregister other workspaces")
				return
			}
			wid = session.Message.Data["Workspace-ID"]

		}
	}

	// You can't unregister the admin account
	if wid == adminWid {
		session.SendStringResponse(403, "FORBIDDEN", "Can't unregister the admin account")
		return
	}

	// Can't delete support or abuse accounts
	for _, builtin := range []string{"support", "abuse"} {
		address, err := dbhandler.ResolveAddress(builtin + "/" + viper.GetString("global.domain"))
		if err != nil {
			session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Write("Unregister: failed to resolve account " + builtin)
			return
		}
		if wid == address {
			session.SendStringResponse(403, "FORBIDDEN",
				fmt.Sprintf("Can't unregister the built-in %s account", builtin))
			return
		}
	}

	// You also don't delete aliases with this command
	isAlias, err := dbhandler.IsAlias(wid)
	if isAlias {
		session.SendStringResponse(403, "FORBIDDEN", "Aliases aren't removed with this command")
		return
	}

	err = dbhandler.RemoveWorkspace(wid)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("Unregister: error removing workspace from db: %s", err.Error())
		return
	}

	err = fshandler.GetFSProvider().RemoveDirectory("/ "+wid, true)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("Unregister: error removing workspace from filesystem: %s", err.Error())
		return
	}

	session.SendStringResponse(202, "UNREGISTERED", "")
}

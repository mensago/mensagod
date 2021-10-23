package main

import (
	"fmt"
	"net"
	"strings"

	ezn "github.com/darkwyrm/goeznacl"
	"github.com/darkwyrm/mensagod/dbhandler"
	"github.com/darkwyrm/mensagod/fshandler"
	"github.com/darkwyrm/mensagod/logging"
	"github.com/darkwyrm/mensagod/misc"
	"github.com/darkwyrm/mensagod/types"
	"github.com/google/uuid"
	"github.com/spf13/viper"
)

func commandGetWID(session *sessionState) {
	// command syntax:
	// GETWID(User-ID, Domain="")
	if !session.Message.HasField("User-ID") {
		session.SendQuickResponse(400, "BAD REQUEST", "")
		return
	}

	uid := types.ToUserID(session.Message.Data["User-ID"])
	if !uid.IsValid() {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad User ID")
		return
	}

	var domain types.DomainT
	if session.Message.HasField("Domain") {
		if err := domain.Set(session.Message.Data["Domain"]); err != nil {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad Domain")
			return
		}
	} else {
		domain.Set(viper.GetString("global.domain"))
	}

	lockout, err := isLocked(session, "widlookup", "")
	if lockout || err != nil {
		return
	}

	address := types.ToMAddressFromParts(uid, domain)
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
	response.Data["Workspace-ID"] = wid.AsString()
	session.SendResponse(*response)
}

func commandPreregister(session *sessionState) {
	// command syntax:
	// PREREG(User-ID="",Workspace-ID="",Domain="")

	if isAdmin, err := session.RequireAdmin(); err != nil || !isAdmin {
		return
	}

	// Just do some basic syntax checks on the user ID
	var uid types.UserID
	if session.Message.HasField("User-ID") {
		if uid.Set(session.Message.Data["User-ID"]) != nil {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad User-ID")
			return
		}

		success, _ := dbhandler.CheckUserID(uid.AsString())
		if success {
			session.SendQuickResponse(408, "RESOURCE EXISTS", "User-ID exists")
			return
		}
	}

	// If the client submits a workspace ID as the user ID, it is considered a request for that
	// specific workspace ID and the user ID is considered blank.
	var wid types.UUID
	if wid.Set(uid.AsString()) == nil {
		uid.Set("")
	} else {
		if session.Message.HasField("Workspace-ID") {
			if wid.Set(session.Message.Data["Workspace-ID"]) != nil {
				session.SendQuickResponse(400, "BAD REQUEST", "Bad Workspace-ID")
				return
			}
		} else {
			id, _ := uuid.NewRandom()
			if wid.Set(id.String()) != nil {
				session.SendQuickResponse(300, "INTERNAL SERVER ERROR",
					"commandPreregister.NewRandom")
				return
			}
		}
	}

	var domain types.DomainT
	if session.Message.HasField("Domain") {
		if domain.Set(session.Message.Data["Domain"]) != nil {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad Domain")
			return
		}
	} else {
		domain.Set(viper.GetString("global.domain"))
	}

	var haswid bool
	if wid != "" {
		haswid, _ = dbhandler.CheckWorkspace(wid.AsString())
		if haswid {
			session.SendQuickResponse(408, "RESOURCE EXISTS", "")
			return
		}
	} else {
		haswid = true
		for haswid {
			wid.Set(uuid.NewString())
			haswid, _ = dbhandler.CheckWorkspace(wid.AsString())
		}
	}

	regcode, err := dbhandler.PreregWorkspace(wid.AsString(), uid.AsString(), domain.AsString(),
		&gDiceWordList, viper.GetInt("security.diceware_wordcount"))
	if err != nil {
		if err.Error() == "uid exists" {
			session.SendQuickResponse(408, "RESOURCE EXISTS", "")
			return
		}
		logging.Write(fmt.Sprintf("Internal server error. commandPreregister.PreregWorkspace. "+
			"Error: %s\n", err))
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	fsp := fshandler.GetFSProvider()
	exists, err := fsp.Exists("/ wsp " + wid.AsString())
	if err != nil {
		logging.Writef("commandPreregister: Failed to check workspace %s existence: %s",
			wid, err)
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}
	if !exists {
		fsp.MakeDirectory("/ wsp " + wid.AsString())
		if err != nil {
			logging.Writef("commandPreregister: Failed to create workspace %s top directory: %s",
				wid, err)
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			return
		}
	}

	response := NewServerResponse(200, "OK")
	if uid != "" {
		response.Data["User-ID"] = uid.AsString()
	}
	response.Data["Workspace-ID"] = wid.AsString()
	response.Data["Domain"] = domain.AsString()
	response.Data["Reg-Code"] = regcode
	session.SendResponse(*response)
}

func commandRegCode(session *sessionState) {
	// command syntax:
	// REGCODE(User-ID, Reg-Code, Password-Hash, Device-ID, Device-Key, Domain="")
	// REGCODE(Workspace-ID, Reg-Code, Password-Hash, Device-ID, Device-Key, Domain="")

	if session.Message.Validate([]string{"Reg-Code", "Password-Hash", "Device-ID",
		"Device-Key"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	devid := types.ToUUID(session.Message.Data["Device-ID"])
	if !devid.IsValid() {
		session.SendQuickResponse(400, "BAD REQUEST", "Invalid Device-ID")
		return
	}

	if len(session.Message.Data["Reg-Code"]) > 128 {
		session.SendQuickResponse(400, "BAD REQUEST", "Invalid reg code")
		return
	}

	// The password field is expected to contain an Argon2id password hash
	isArgon, err := ezn.IsArgonHash(session.Message.Data["Password-Hash"])
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "RegCode.1")
		logging.Writef("commandRegCode: error check password hash: %s", err)
		return
	}

	if !isArgon {
		session.SendQuickResponse(400, "BAD REQUEST", "Invalid password hash")
		return
	}

	// A workspace ID is a valid UserID, so we can pretty much just handle both cases the same way
	var msgid types.UserID
	if session.Message.HasField("User-ID") {
		if msgid.Set(session.Message.Data["User-ID"]) != nil {
			session.SendQuickResponse(400, "BAD REQUEST", "Invalid User-ID")
			return
		}
	} else if session.Message.HasField("Workspace-ID") {
		if msgid.Set(session.Message.Data["Workspace-ID"]) != nil && msgid.IsWID() {
			session.SendQuickResponse(400, "BAD REQUEST", "Invalid Workspace-ID")
			return
		}
	} else {
		session.SendQuickResponse(400, "BAD REQUEST", "")
		return
	}

	var domain types.DomainT
	if session.Message.HasField("Domain") {
		if err := domain.Set(session.Message.Data["Domain"]); err != nil {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad Domain")
			return
		}
	}
	if !domain.IsValid() {
		domain.Set(viper.GetString("global.domain"))
	}

	// If lockTime is non-empty, it means that the client has exceeded the configured threshold.
	// At this point, the connection should be terminated. However, an empty lockTime
	// means that although there has been a failure, the count for this IP address is
	// still under the limit.
	lockout, err := isLocked(session, "prereg", "")
	if lockout || err != nil {
		return
	}

	var devkey ezn.CryptoString
	if devkey.Set(session.Message.Data["Device-Key"]) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad Device-Key")
		return
	}

	if devkey.Prefix != "CURVE25519" {
		session.SendQuickResponse(309, "ENCRYPTION TYPE NOT SUPPORTED", "Supported: CURVE25519")
		return
	}

	wid, uid, err := dbhandler.CheckRegCode(msgid.AsString(), domain.AsString(), msgid.IsWID(),
		session.Message.Data["Reg-Code"])

	if wid == "" {
		// Regardless of whether or not an error has been returned from log, we exit here. In this
		// case, state doesn't matter.
		if err == misc.ErrNotFound {
			session.SendQuickResponse(404, "NOT FOUND", "")
		} else {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "RegCode.2")
			logging.Writef("Internal server error. commandRegCode.CheckRegCode. Error: %s\n", err)
		}
		logFailure(session, "prereg", "")
		return
	}

	err = dbhandler.AddWorkspace(wid, uid, domain.AsString(), session.Message.Data["Password-Hash"],
		"active", "identity")
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "RegCode.3")
		logging.Writef("Internal server error. commandRegCode.AddWorkspace. Error: %s\n", err)
		return
	}

	err = dbhandler.SetWorkspaceStatus(wid, "active")
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "RegCode.4")
		logging.Writef("Internal server error. commandRegCode.SetWorkspaceStatus. Error: %s\n", err)
		return
	}

	err = dbhandler.AddDevice(wid, devid.AsString(), devkey, "active")
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "RegCode.5")
		logging.Writef("Internal server error. commandRegCode.AddDevice. Error: %s\n", err)
		return
	}

	err = dbhandler.DeleteRegCode(msgid.AsString(), domain.AsString(), false,
		session.Message.Data["Reg-Code"])
	if err != nil {
		logging.Writef("Internal server error. commandRegCode.DeleteRegCode. Error: %s\n", err)
		return
	}

	response := NewServerResponse(201, "REGISTERED")
	response.Data["Workspace-ID"] = wid
	response.Data["User-ID"] = uid
	response.Data["Domain"] = domain.AsString()
	session.SendResponse(*response)
}

func commandRegister(session *sessionState) {
	// command syntax:
	// REGISTER(Workspace-ID, Password-Hash, Device-ID, Device-Key, User-ID="", Type="")

	if session.Message.Validate([]string{"Workspace-ID", "Password-Hash", "Device-ID",
		"Device-Key"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	wid := types.ToUUID(session.Message.Data["Workspace-ID"])
	if !wid.IsValid() {
		session.SendQuickResponse(400, "BAD REQUEST", "Invalid Workspace-ID")
		return
	}

	devid := types.ToUUID(session.Message.Data["Device-ID"])
	if !devid.IsValid() {
		session.SendQuickResponse(400, "BAD REQUEST", "Invalid Device-ID")
		return
	}

	// Just do some basic syntax checks on the user ID
	var uid types.UserID
	if session.Message.HasField("User-ID") {

		if uid.Set(session.Message.Data["User-ID"]) != nil {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad User-ID")
			return
		}
	}

	if _, err := ezn.IsArgonHash(session.Message.Data["Password-Hash"]); err != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Invalid Password Hash")
		return
	}

	wtype := "identity"
	if session.Message.HasField("Type") {
		wtype = session.Message.Data["Type"]
		if wtype != "shared" && wtype != "identity" {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad Type")
			return
		}

		// TODO: POSTDEMO: Eliminate this when shared workspaces are implemented
		if wtype == "shared" {
			session.SendQuickResponse(301, "NOT IMPLEMENTED", "")
			return
		}
	}
	regType := strings.ToLower(viper.GetString("global.registration"))

	if regType == "private" {
		session.SendQuickResponse(304, "REGISTRATION CLOSED", "")
		return
	}

	success, _ := dbhandler.CheckWorkspace(wid.AsString())
	if success {
		response := NewServerResponse(408, "RESOURCE EXISTS")
		response.Data["Field"] = "Workspace-ID"
		session.SendResponse(*response)
		return
	}

	if session.Message.HasField("User-ID") {
		success, _ = dbhandler.CheckUserID(uid.AsString())
		if success {
			response := NewServerResponse(408, "RESOURCE EXISTS")
			response.Data["Field"] = "User-ID"
			session.SendResponse(*response)
			return
		}
	}

	// TODO: POSTDEMO: Check number of recent registration requests from this IP

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
			session.SendQuickResponse(304, "REGISTRATION CLOSED", "")
			return
		}
		workspaceStatus = "active"
	case "moderated":
		workspaceStatus = "pending"
	default:
		workspaceStatus = "active"
	}

	var devkey ezn.CryptoString
	if devkey.Set(session.Message.Data["Device-Key"]) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad Device-Key")
		return
	}

	if devkey.Prefix != "CURVE25519" {
		session.SendQuickResponse(309, "ENCRYPTION TYPE NOT SUPPORTED", "Supported: CURVE25519")
		return
	}

	err := dbhandler.AddWorkspace(wid.AsString(), uid.AsString(), viper.GetString("global.domain"),
		session.Message.Data["Password-Hash"], workspaceStatus, wtype)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("Internal server error. commandRegister.AddWorkspace. Error: %s\n", err)
		return
	}

	err = dbhandler.AddDevice(wid.AsString(), devid.AsString(), devkey, "active")
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("Internal server error. commandRegister.AddDevice. Error: %s\n", err)
		return
	}

	fsp := fshandler.GetFSProvider()
	exists, err := fsp.Exists("/ " + wid.AsString())
	if err != nil {
		logging.Writef("commandPreregister: Failed to check workspace %s existence: %s", wid, err)
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}
	if !exists {
		fsp.MakeDirectory("/ " + wid.AsString())
		if err != nil {
			logging.Writef("commandPreregister: Failed to create workspace %s top directory: %s",
				wid, err)
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			return
		}
	}

	if regType == "moderated" {
		session.SendQuickResponse(101, "PENDING", "")
	} else {
		response := NewServerResponse(201, "REGISTERED")
		response.Data["Domain"] = viper.GetString("global.domain")
		session.SendResponse(*response)
	}
}

func commandUnrecognized(session *sessionState) {
	// command used when not recognized
	session.SendQuickResponse(400, "BAD REQUEST", "Unrecognized command")
}

func commandUnregister(session *sessionState) {
	// command syntax:
	// UNREGISTER(Password-Hash)

	if !session.RequireLogin() {
		return
	}

	if !session.Message.HasField("Password-Hash") {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	if _, err := ezn.IsArgonHash(session.Message.Data["Password-Hash"]); err != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Invalid Password Hash")
		return
	}

	match, err := dbhandler.CheckPassword(session.WID.AsString(), session.Message.Data["Password-Hash"])
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("Unregister: error checking password: %s", err.Error())
		return
	}
	if !match {
		session.SendQuickResponse(401, "UNAUTHORIZED", "Password mismatch")
		return
	}

	regType := strings.ToLower(viper.GetString("global.registration"))
	if regType == "private" || regType == "moderated" {
		// TODO: submit admin request to delete workspace
		// session.SendQuickResponse(101, "PENDING", "Pending administrator approval")
		session.SendQuickResponse(301, "NOT IMPLEMENTED", "Not implemented yet. Sorry!")
		return
	}

	adminAddress, err := GetAdmin()
	if err != nil {
		return
	}

	// This command can be used to unregister other workspaces, but only the admin account is
	// allowed to do this
	wid := session.WID
	if session.Message.HasField("Workspace-ID") {
		tempWid := types.ToUUID(session.Message.Data["Workspace-ID"])
		if !tempWid.IsValid() {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad Workspace-ID")
			return
		}

		if !session.WID.Equals(tempWid) {

			if !session.WID.Equals(adminAddress.ID) {
				session.SendQuickResponse(401, "UNAUTHORIZED",
					"Only admin can unregister other workspaces")
				return
			}
			wid = tempWid

		}
	}

	// You can't unregister the admin account
	if wid.Equals(adminAddress.ID) {
		session.SendQuickResponse(403, "FORBIDDEN", "Can't unregister the admin account")
		return
	}

	// Can't delete support or abuse accounts
	for _, builtin := range []string{"support", "abuse"} {
		currentAddress := types.MAddress{IDType: 2, ID: builtin,
			Domain: types.DomainT(viper.GetString("global.domain"))}
		resolved, err := dbhandler.ResolveAddress(currentAddress)
		if err != nil {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Write("Unregister: failed to resolve account " + builtin)
			return
		}
		if wid.Equals(resolved) {
			session.SendQuickResponse(403, "FORBIDDEN",
				fmt.Sprintf("Can't unregister the built-in %s account", builtin))
			return
		}
	}

	// You also don't delete aliases with this command
	isAlias, _ := dbhandler.IsAlias(wid.AsString())
	if isAlias {
		session.SendQuickResponse(403, "FORBIDDEN", "Aliases aren't removed with this command")
		return
	}

	err = dbhandler.RemoveWorkspace(wid.AsString())
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("Unregister: error removing workspace from db: %s", err.Error())
		return
	}

	err = fshandler.GetFSProvider().RemoveDirectory("/ wsp "+wid.AsString(), true)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("Unregister: error removing workspace from filesystem: %s", err.Error())
		return
	}

	session.SendQuickResponse(202, "UNREGISTERED", "")
}

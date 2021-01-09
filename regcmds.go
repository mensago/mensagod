package main

import (
	"regexp"
	"strings"

	"github.com/darkwyrm/anselusd/dbhandler"
	"github.com/darkwyrm/b85"
	"github.com/google/uuid"
	"github.com/spf13/viper"
)

func commandPreregister(session *sessionState) {
	// command syntax:
	// PREREG(User-ID="",Workspace-ID="",Domain="")

	// Just do some basic syntax checks on the user ID
	uid := ""
	if session.Message.HasField("User-ID") {
		uid = session.Message.Data["User-ID"]
		if strings.ContainsAny(uid, "/\"") {
			session.SendStringResponse(400, "BAD REQUEST", "Bad User-ID")
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

	ipv4Pat := regexp.MustCompile("([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}):[0-9]+")
	mIP4 := ipv4Pat.FindStringSubmatch(session.Connection.RemoteAddr().String())

	remoteIP4 := ""
	if len(mIP4) == 2 {
		remoteIP4 = mIP4[1]
	}

	// Preregistration must be done from the server itself
	mIP6, _ := regexp.MatchString("(::1):[0-9]+", session.Connection.RemoteAddr().String())

	if !mIP6 && (remoteIP4 == "" || remoteIP4 != "127.0.0.1") {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
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

	regcode, err := dbhandler.PreregWorkspace(wid, uid, domain, &gRegWordList,
		viper.GetInt("global.registration_wordcount"))
	if err != nil {
		if err.Error() == "uid exists" {
			session.SendStringResponse(408, "RESOURCE EXISTS", "")
			return
		}
		ServerLog.Printf("Internal server error. commandPreregister.PreregWorkspace. Error: %s\n", err)
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		return
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
	// REGCODE(User-ID, Reg-Code, Password-Hash, Device-ID, Device-KeyType, Device-Key)
	// REGCODE(Workspace-ID, Reg-Code, Password-Hash, Device-ID, Device-KeyType, Device-Key)

	if session.Message.Validate([]string{"Reg-Code", "Password-Hash", "Device-ID", "Device-KeyType",
		"Device-Key"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}
	if !dbhandler.ValidateUUID(session.Message.Data["Device-ID"]) {
		session.SendStringResponse(400, "BAD REQUEST", "Invalid Device-ID")
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

	// If lockTime is non-empty, it means that the client has exceeded the configured threshold.
	// At this point, the connection should be terminated. However, an empty lockTime
	// means that although there has been a failure, the count for this IP address is
	// still under the limit.
	lockTime, err := dbhandler.CheckLockout("prereg", session.Connection.RemoteAddr().String(),
		session.Connection.RemoteAddr().String())

	if err != nil {
		panic(err)
	}

	if len(lockTime) > 0 {
		var response ServerResponse
		response.Code = 405
		response.Status = "TERMINATED"
		response.Data["Lock-Time"] = lockTime
		session.SendResponse(response)
		session.IsTerminating = true
	}

	if session.Message.Data["Device-KeyType"] != "CURVE25519" {
		session.SendStringResponse(309, "ENCRYPTION TYPE NOT SUPPORTED", "Supported: CURVE25519")
		return
	}

	_, err = b85.Decode(session.Message.Data["Device-Key"])
	if err != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Device-Key Base85 decoding error")
		return
	}

	var wid string
	if session.Message.HasField("Workspace-ID") {
		wid, err = dbhandler.CheckRegCode(session.Message.Data["Workspace-ID"], true,
			session.Message.Data["Reg-Code"])
	} else {
		wid, err = dbhandler.CheckRegCode(session.Message.Data["User-ID"], true,
			session.Message.Data["Reg-Code"])
	}

	if wid == "" {
		dbhandler.LogFailure("prereg", session.Connection.RemoteAddr().String(),
			session.Connection.RemoteAddr().String())

		lockTime, err = dbhandler.CheckLockout("prereg", session.Connection.RemoteAddr().String(),
			session.Connection.RemoteAddr().String())

		if err != nil {
			panic(err)
		}

		if len(lockTime) > 0 {
			session.WriteClient(strings.Join([]string{"405 TERMINATED ", lockTime, "\r\n"}, " "))
			session.IsTerminating = true
			return
		}
	}

	err = dbhandler.AddWorkspace(wid, session.Message.Data["Password-Hash"], "active")
	if err != nil {
		ServerLog.Printf("Internal server error. commandRegister.AddWorkspace. Error: %s\n", err)
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
	}

	devid := uuid.New().String()
	err = dbhandler.AddDevice(wid, devid, "CURVE25519", session.Message.Data["Device-Key"],
		"active")
	if err != nil {
		var response ServerResponse
		response.Code = 300
		response.Status = "INTERNAL SERVER ERROR"
		response.Data["Error"] = err.Error()
		session.SendResponse(response)
	}

	session.SendStringResponse(201, "REGISTERED", "")
}

func commandRegister(session *sessionState) {
	// command syntax:
	// REGISTER(Workspace-ID, Password-Hash, Device-KeyType, Device-Key)

	if session.Message.Validate([]string{"Workspace-ID", "Password-Hash", "Device-KeyType",
		"Device-Key"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}
	if !dbhandler.ValidateUUID(session.Message.Data["Workspace-ID"]) {
		session.SendStringResponse(400, "BAD REQUEST", "Invalid Workspace-ID")
		return
	}

	regType := strings.ToLower(viper.GetString("global.registration"))

	ipv4Pat := regexp.MustCompile("([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}):[0-9]+")
	mIP4 := ipv4Pat.FindStringSubmatch(session.Connection.RemoteAddr().String())

	remoteIP4 := ""
	if len(mIP4) == 2 {
		remoteIP4 = mIP4[1]
	}

	if regType == "private" {
		// If registration is set to private, registration must be done from the server itself.
		mIP6, _ := regexp.MatchString("(::1):[0-9]+", session.Connection.RemoteAddr().String())

		if !mIP6 && (remoteIP4 == "" || remoteIP4 != "127.0.0.1") {
			session.SendStringResponse(304, "REGISTRATION CLOSED", "")
			return
		}
	}

	success, _ := dbhandler.CheckWorkspace(session.Message.Data["Workspace-ID"])
	if success {
		session.SendStringResponse(408, "RESOURCE EXISTS", "")
		return
	}

	// TODO: Check number of recent registration requests from this IP

	var workspaceStatus string
	switch regType {
	case "network":
		// TODO: Check that remote address is within permitted subnet
		session.SendStringResponse(301, "NOT IMPLEMENTED",
			"Network registration mode not implemented. Sorry!")
		return
	case "moderated":
		workspaceStatus = "pending"
	default:
		workspaceStatus = "active"
	}

	if session.Message.Data["Device-KeyType"] != "CURVE25519" {
		session.SendStringResponse(309, "ENCRYPTION TYPE NOT SUPPORTED", "Supported: CURVE25519")
		return
	}

	// An encryption key can be basically anything for validation purposes, but we can at least
	// make sure that the encoding is valid.
	_, err := b85.Decode(session.Message.Data["Device-Key"])
	if err != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Device-Key Base85 decoding error")
		return
	}

	err = dbhandler.AddWorkspace(session.Message.Data["Workspace-ID"],
		session.Message.Data["Password-Hash"], workspaceStatus)
	if err != nil {
		ServerLog.Printf("Internal server error. commandRegister.AddWorkspace. Error: %s\n", err)
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
	}

	devid := uuid.New().String()
	err = dbhandler.AddDevice(session.Message.Data["Workspace-ID"], devid, "CURVE25519",
		session.Message.Data["Device-Key"], "active")
	if err != nil {
		ServerLog.Printf("Internal server error. commandRegister.AddDevice. Error: %s\n", err)
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
	}

	if regType == "moderated" {
		session.SendStringResponse(101, "PENDING", "")
	} else {
		var response ServerResponse
		response.Code = 201
		response.Status = "REGISTERED"
		response.Data["Device-ID"] = devid
		session.SendResponse(response)
	}
}

func commandUnrecognized(session *sessionState) {
	// command used when not recognized
	session.SendStringResponse(400, "BAD REQUEST", "Unrecognized command")
}

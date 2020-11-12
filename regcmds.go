package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/darkwyrm/anselusd/dbhandler"
	"github.com/darkwyrm/b85"
	"github.com/google/uuid"
	"github.com/spf13/viper"
)

func commandPreregister(session *sessionState) {
	// command syntax:
	// PREREG opt_uid

	if len(session.Tokens) > 2 {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	// Just do some basic syntax checks on the user ID
	userID := ""
	if len(session.Tokens) == 2 {
		userID = session.Tokens[1]
		if strings.ContainsAny(userID, "/\"") || dbhandler.ValidateUUID(userID) {
			session.WriteClient("400 BAD REQUEST\r\n")
			return
		}
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
		session.WriteClient("401 UNAUTHORIZED\r\n")
		return
	}

	haswid := true
	var wid string
	for haswid {
		wid = uuid.New().String()
		haswid, _ = dbhandler.CheckWorkspace(wid)
	}

	regcode, err := dbhandler.PreregWorkspace(wid, userID, &gRegWordList,
		viper.GetInt("global.registration_wordcount"))
	if err != nil {
		if err.Error() == "uid exists" {
			session.WriteClient("408 RESOURCE EXISTS\r\n")
			return
		}
		ServerLog.Printf("Internal server error. commandPreregister.PreregWorkspace. Error: %s\n", err)
		session.WriteClient("300 INTERNAL SERVER ERROR\r\n")
		return
	}

	if userID != "" {
		session.WriteClient(fmt.Sprintf("200 OK %s %s %s\r\n", wid, regcode, userID))
	} else {
		session.WriteClient(fmt.Sprintf("200 OK %s %s\r\n", wid, regcode))
	}
}

func commandRegCode(session *sessionState) {
	// command syntax:
	// REGCODE <uid|wid> <regcode> <password_hash> <deviceID> <devkeytype> <devkey>

	if len(session.Tokens) != 7 {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	id := session.Tokens[1]

	// check to see if this is a workspace ID
	isWid := dbhandler.ValidateUUID(id)

	if !isWid && strings.ContainsAny(id, "/\"") {
		session.WriteClient("400 BAD REQUEST\r\n")
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
		session.WriteClient(strings.Join([]string{"405 TERMINATED ", lockTime, "\r\n"}, " "))
		session.IsTerminating = true
	}

	if (len(session.Tokens[3]) < 8 || len(session.Tokens[3]) > 120) ||
		!dbhandler.ValidateUUID(session.Tokens[4]) {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	if session.Tokens[5] != "curve25519" {
		session.WriteClient("309 ENCRYPTION TYPE NOT SUPPORTED\r\n")
		return
	}

	_, err = b85.Decode(session.Tokens[6])
	if err != nil {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	wid, err := dbhandler.CheckRegCode(id, isWid, session.Tokens[2])

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

	if err != nil {
		session.WriteClient("300 INTERNAL SERVER ERROR\r\n")
		return
	}

	err = dbhandler.AddWorkspace(wid, session.Tokens[3], "active")
	if err != nil {
		ServerLog.Printf("Internal server error. commandRegister.AddWorkspace. Error: %s\n", err)
		session.WriteClient("300 INTERNAL SERVER ERROR\r\n")
	}

	devid := uuid.New().String()
	err = dbhandler.AddDevice(wid, devid, session.Tokens[5], session.Tokens[6],
		"active")
	if err != nil {
		ServerLog.Printf("Internal server error. commandRegister.AddDevice. Error: %s\n", err)
		session.WriteClient("300 INTERNAL SERVER ERROR\r\n")
	}

	session.WriteClient("201 REGISTERED\r\n")
}

func commandRegister(session *sessionState) {
	// command syntax:
	// REGISTER <WID> <passwordHash> <algorithm> <devkey>

	if len(session.Tokens) != 5 || !dbhandler.ValidateUUID(session.Tokens[1]) {
		session.WriteClient("400 BAD REQUEST\r\n")
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
			session.WriteClient("304 REGISTRATION CLOSED\r\n")
			return
		}
	}

	success, _ := dbhandler.CheckWorkspace(session.Tokens[1])
	if success {
		session.WriteClient("408 RESOURCE EXISTS\r\n")
		return
	}

	// TODO: Check number of recent registration requests from this IP

	var workspaceStatus string
	switch regType {
	case "network":
		// TODO: Check that remote address is within permitted subnet
		session.WriteClient("301 NOT IMPLEMENTED\r\n")
		return
	case "moderated":
		workspaceStatus = "pending"
	default:
		workspaceStatus = "active"
	}

	// Just some basic sanity checks on the password hash.
	if len(session.Tokens[2]) < 8 || len(session.Tokens[2]) > 120 {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	if session.Tokens[3] != "curve25519" {
		session.WriteClient("309 ENCRYPTION TYPE NOT SUPPORTED\r\n")
		return
	}

	// An encryption key can be basically anything for validation purposes, but we can at least
	// make sure that the encoding is valid.
	_, err := b85.Decode(session.Tokens[4])
	if err != nil {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	err = dbhandler.AddWorkspace(session.Tokens[1], session.Tokens[2], workspaceStatus)
	if err != nil {
		ServerLog.Printf("Internal server error. commandRegister.AddWorkspace. Error: %s\n", err)
		session.WriteClient("300 INTERNAL SERVER ERROR\r\n")
	}

	devid := uuid.New().String()
	err = dbhandler.AddDevice(session.Tokens[1], devid, session.Tokens[3], session.Tokens[4],
		"active")
	if err != nil {
		ServerLog.Printf("Internal server error. commandRegister.AddDevice. Error: %s\n", err)
		session.WriteClient("300 INTERNAL SERVER ERROR\r\n")
	}

	if regType == "moderated" {
		session.WriteClient("101 PENDING")
	} else {
		session.WriteClient(fmt.Sprintf("201 REGISTERED %s\r\n", devid))
	}
}

func commandUnrecognized(session *sessionState) {
	// command used when not recognized
	session.WriteClient("400 BAD REQUEST\r\n")
}

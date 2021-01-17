package main

import (
	"crypto/ed25519"
	"fmt"
	"strconv"

	"github.com/darkwyrm/anselusd/cryptostring"
	"github.com/darkwyrm/anselusd/dbhandler"
	"github.com/darkwyrm/anselusd/keycard"
	"github.com/darkwyrm/b85"
	"github.com/spf13/viper"
)

func commandAddEntry(session *sessionState) {
	// Command syntax:
	// ADDENTRY(Base-Entry)

	// 1) Client sends the `ADDENTRY` command, attaching the entry data.
	// 2) The server then checks compliance of the entry data. Assuming that it complies, the server
	//    generates a cryptographic signature and responds with `100 CONTINUE`, returning the
	//    signature, the hash of the data, and the hash of the previous entry in the database.
	// 3) The client verifies the signature against the organization’s verification key. This has
	//    the added benefit of ensuring that none of the fields were altered by the server and that
	//    the signature is valid.
	// 4) The client appends the hash from the previous entry as the `Previous-Hash` field
	// 5) The client verifies the hash value for the entry from the server and sets the `Hash` field
	// 6) The client signs the entry as the `User-Signature` field and then uploads the result to
	//    the server.
	// 7) Once uploaded, the server validates the `Hash` and `User-Signature` fields, and,
	//    assuming that all is well, adds it to the keycard database and returns `200 OK`.

	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "Login required")
		return
	}

	// The User-Signature field can only be part of the message once the AddEntry command has
	// started and the org signature and hashes have been added. If present, it constitutes an
	// out-of-order request
	if session.Message.Validate([]string{"Base-Entry"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing Base-Entry field")
		return
	}

	if session.Message.HasField("User-Signature") {
		session.SendStringResponse(400, "BAD REQUEST", "Received out-of-order User-Signature field")
		return
	}

	// We've managed to read data from the client. Now for some extensive validation.

	var entry *keycard.Entry
	entry, err := keycard.NewEntryFromData(session.Message.Data["Base-Entry"])
	if err != nil {
		session.SendStringResponse(411, "BAD KEYCARD DATA", "")
		return
	}
	if !entry.IsDataCompliant() {
		session.SendStringResponse(412, "NONCOMPLIANT KEYCARD DATA", "")
		return
	}

	if entry.Fields["Workspace-ID"] != session.WID {
		session.SendStringResponse(411, "BAD KEYCARD DATA", "Workspace doesn't match login")
		return
	}

	// admin, support, and abuse can't change their user IDs
	adminAddresses := []string{"admin", "support", "abuse"}
	for _, address := range adminAddresses {
		currentAddress := address + "/" + viper.GetString("global.domain")
		currentWid, err := dbhandler.ResolveAddress(currentAddress)
		if err != nil {
			session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		}
		if session.WID == currentWid {
			if entry.Fields["User-ID"] != address {
				session.SendStringResponse(411, "BAD KEYCARD DATA",
					"Admin, Support, and Abuse can't change their user IDs")
				return
			}
		}
	}

	adminAddress := "admin/" + viper.GetString("global.domain")
	adminWid, err := dbhandler.ResolveAddress(adminAddress)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
	}
	if session.WID == adminWid {
		if entry.Fields["User-ID"] != "admin" {
			session.SendStringResponse(411, "BAD KEYCARD DATA", "Admin can't change its user ID")
			return
		}
	}

	// IsDataCompliant performs all of the checks we need to ensure that the data given to us by the
	// client EXCEPT checking the expiration
	var isExpired bool
	isExpired, err = entry.IsExpired()
	if err != nil {
		session.SendStringResponse(411, "BAD KEYCARD DATA", err.Error())
		return
	}
	if isExpired {
		session.SendStringResponse(412, "NONCOMPLIANT KEYCARD DATA", "Keycard entry is expired")
		return
	}

	tempStr, err := dbhandler.GetUserEntries(entry.Fields["Workspace-ID"], 0, 0)
	if len(tempStr) != 0 && err == nil {

		// If there are previous entries for the workspace, the chain of trust must be validated.
		prevEntry, err := keycard.NewEntryFromData(tempStr[0])
		if err != nil {
			session.SendStringResponse(300, "INTERNAL SERVER ERRROR",
				"Failure to create entry from data")
			ServerLog.Println(fmt.Sprintf("ERROR AddEntry: previous keycard entry invalid for "+
				"workspace %s", entry.Fields["Workspace-ID"]))
			fmt.Println(fmt.Sprintf("ERROR AddEntry: previous keycard entry invalid for "+
				"workspace %s", entry.Fields["Workspace-ID"]))
			return
		}

		isOK, err := entry.VerifyChain(prevEntry)
		if !isOK || err != nil {
			session.SendStringResponse(412, "NONCOMPLIANT KEYCARD DATA",
				"Entry failed to chain verify")
			return
		}
	}

	// If we managed to get this far, we can (theoretically) trust the initial data set given to us
	// by the client. Here we sign the data with the organization's signing key

	pskstring, err := dbhandler.GetPrimarySigningKey()
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERRROR", "")
		ServerLog.Println("ERROR AddEntry: missing primary signing key in database.")
		fmt.Println("ERROR AddEntry: missing primary signing key in database.")
		return
	}

	var psk cryptostring.CryptoString
	err = psk.Set(pskstring)
	if err != nil || psk.RawData() == nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERRROR", "")
		ServerLog.Println("ERROR AddEntry: corrupted primary signing key in database.")
		fmt.Println("ERROR AddEntry: corrupted primary signing key in database.")
		return
	}

	// We bypass the nacl/sign module because it requires a 64-bit private key. We, however, pass
	// around the 32-bit ed25519 seeds used to generate the keys. Thus, we have to skip using
	// nacl.Sign() and go directly to the equivalent code in the ed25519 module.
	pskBytes := ed25519.NewKeyFromSeed(psk.RawData())
	rawSignature := ed25519.Sign(pskBytes, entry.MakeByteString(-1))
	if rawSignature == nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERRROR", "")
		ServerLog.Println("ERROR AddEntry: failed to org sign entry.")
		fmt.Println("ERROR AddEntry: failed to org sign entry.")
		return
	}
	signature := "ED25519:" + b85.Encode(rawSignature)
	entry.Signatures["Organization"] = signature

	rawLastEntry, err := dbhandler.GetLastEntry()
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERRROR", "")
		ServerLog.Println("ERROR AddEntry: failed to obtain last entry.")
		fmt.Println("ERROR AddEntry: failed to obtain last entry.")
		return
	}

	lastEntry, err := keycard.NewEntryFromData(rawLastEntry)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERRROR", "")
		ServerLog.Println("ERROR AddEntry: failed to create entry from last entry data.")
		fmt.Println("ERROR AddEntry: failed to create entry from last entry data.")
		return
	}
	entry.PrevHash = lastEntry.Hash

	err = entry.GenerateHash("BLAKE2B-256")
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERRROR", "")
		ServerLog.Println("ERROR AddEntry: failed to hash entry.")
		fmt.Println("ERROR AddEntry: failed to hash entry.")
	}

	response := NewServerResponse(100, "CONTINUE")
	response.Data["Hash"] = entry.Hash
	response.Data["Previous-Hash"] = entry.PrevHash
	response.Data["Organization-Signature"] = signature
	err = session.SendResponse(*response)
	if err != nil {
		return
	}

	request, err := session.GetRequest()
	if err != nil {
		return
	}
	if request.Action != "ADDENTRY" ||
		request.Validate([]string{"User-Signature"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing User-Signature field")
		return
	}

	entry.Signatures["User"] = request.Data["User-Signature"]
	if !entry.IsCompliant() {
		session.SendStringResponse(412, "NONCOMPLIANT KEYCARD DATA", "")
		return
	}

	var crkey cryptostring.CryptoString
	err = crkey.Set(entry.Fields["Contact-Request-Verification-Key"])
	if err != nil {
		session.SendStringResponse(413, "INVALID SIGNATURE", "Bad Contact-Request-Verification-Key")
		return
	}
	verified, err := entry.VerifySignature(crkey, "User")
	if err != nil || !verified {
		session.SendStringResponse(413, "INVALID SIGNATURE", "User-Signature failed to verify")
		return
	}

	err = dbhandler.AddEntry(entry)
	if err == nil {
		session.SendStringResponse(200, "OK", "")
	} else {
		session.SendStringResponse(300, "INTERNAL SERVER ERRROR", "")
		ServerLog.Println("ERROR AddEntry: failed to add entry.")
		fmt.Println("ERROR AddEntry: failed to add entry.")
	}
}

func commandOrgCard(session *sessionState) {
	// command syntax:
	// ORGCARD(Start-Index, End-Index=0)

	if !session.Message.HasField("Start-Index") {
		session.SendStringResponse(400, "BAD REQUEST", "Missing Start-Index")
		return
	}

	var startIndex, endIndex int
	var err error
	startIndex, err = strconv.Atoi(session.Message.Data["Start-Index"])
	if err != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Bad Start-Index")
		return
	}

	if session.Message.HasField("End-Index") {
		endIndex, err = strconv.Atoi(session.Message.Data["End-Index"])
		if err != nil {
			session.SendStringResponse(400, "BAD REQUEST", "Bad End-Index")
			return
		}
	}

	entries, err := dbhandler.GetOrgEntries(startIndex, endIndex)
	entryCount := len(entries)
	var response ServerResponse
	if entryCount > 0 {
		transmissionSize := uint64(0)
		for _, entry := range entries {
			// 56 is the size of the header and footer and accompanying line terminators
			transmissionSize += uint64(len(entry) + len("----- BEGIN ORG ENTRY -----\r\n") +
				len("----- END ORG ENTRY -----\r\n"))
		}

		response.Code = 104
		response.Status = "TRANSFER"
		response.Data = make(map[string]string)
		response.Data["Item-Count"] = fmt.Sprintf("%d", entryCount)
		response.Data["Total-Size"] = fmt.Sprintf("%d", transmissionSize)
		if session.SendResponse(response) != nil {
			return
		}

		request, err := session.GetRequest()
		if err != nil || request.Action != "TRANSFER" {
			session.SendStringResponse(400, "BAD REQUEST", "")
			return
		}

		totalBytes := 0
		for _, entry := range entries {
			bytesWritten, err := session.WriteClient("----- BEGIN ORG ENTRY -----\r\n" + entry +
				"----- END ORG ENTRY -----\r\n")
			if err != nil {
				return
			}
			totalBytes += bytesWritten
		}
	} else {
		session.SendStringResponse(404, "NOT FOUND", "")
	}
}

func commandUserCard(session *sessionState) {
	// command syntax:
	// USERCARD(Owner, Start-Index, End-Index=0)

	if session.Message.Validate([]string{"Owner", "Start-Index"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing Start-Index")
		return
	}

	if dbhandler.GetAnselusAddressType(session.Message.Data["Owner"]) == 0 {
		session.SendStringResponse(400, "BAD REQUEST", "Missing Owner")
		return
	}

	wid, err := dbhandler.ResolveAddress(session.Message.Data["Owner"])
	if wid == "" {
		session.SendStringResponse(404, "NOT FOUND", "")
		return
	}

	var startIndex, endIndex int
	startIndex, err = strconv.Atoi(session.Message.Data["Start-Index"])
	if err != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Bad Start-Index")
		return
	}

	if session.Message.HasField("End-Index") {
		endIndex, err = strconv.Atoi(session.Message.Data["End-Index"])
		if err != nil {
			session.SendStringResponse(400, "BAD REQUEST", "Bad End-Index")
			return
		}
	}

	entries, err := dbhandler.GetUserEntries(wid, startIndex, endIndex)
	entryCount := len(entries)
	var response ServerResponse
	if entryCount > 0 {
		transmissionSize := uint64(0)
		for _, entry := range entries {
			// 56 is the size of the header and footer and accompanying line terminators
			transmissionSize += uint64(len(entry) + len("----- BEGIN USER ENTRY -----\r\n") +
				len("----- END USER ENTRY -----\r\n"))
		}

		response.Code = 104
		response.Status = "TRANSFER"
		response.Data = make(map[string]string)
		response.Data["Item-Count"] = fmt.Sprintf("%d", entryCount)
		response.Data["Total-Size"] = fmt.Sprintf("%d", transmissionSize)
		if session.SendResponse(response) != nil {
			return
		}

		request, err := session.GetRequest()
		if err != nil || request.Action != "TRANSFER" {
			session.SendStringResponse(400, "BAD REQUEST", "")
			return
		}

		totalBytes := 0
		for _, entry := range entries {
			bytesWritten, err := session.WriteClient("----- BEGIN USER ENTRY -----\r\n" + entry +
				"----- END USER ENTRY -----\r\n")
			if err != nil {
				return
			}
			totalBytes += bytesWritten
		}
	} else {
		session.SendStringResponse(404, "NOT FOUND", "")
	}
}

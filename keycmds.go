package main

import (
	"crypto/ed25519"
	"fmt"
	"strconv"
	"strings"

	"github.com/darkwyrm/b85"
	ezn "github.com/darkwyrm/goeznacl"
	"github.com/darkwyrm/mensagod/dbhandler"
	"github.com/darkwyrm/mensagod/keycard"
	"github.com/darkwyrm/mensagod/logging"
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
		session.SendQuickResponse(401, "UNAUTHORIZED", "Login required")
		return
	}

	// The User-Signature field can only be part of the message once the AddEntry command has
	// started and the org signature and hashes have been added. If present, it constitutes an
	// out-of-order request
	if session.Message.Validate([]string{"Base-Entry"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing Base-Entry field")
		return
	}

	if session.Message.HasField("User-Signature") {
		session.SendQuickResponse(400, "BAD REQUEST", "Received out-of-order User-Signature field")
		return
	}

	// We've managed to read data from the client. Now for some extensive validation.

	var entry *keycard.Entry
	entry, err := keycard.NewEntryFromData(session.Message.Data["Base-Entry"])
	if err != nil {
		session.SendQuickResponse(411, "BAD KEYCARD DATA", "Couldn't create entry from data")
		return
	}
	if !entry.IsDataCompliant() {
		session.SendQuickResponse(412, "NONCOMPLIANT KEYCARD DATA", "")
		return
	}

	wid := strings.ToLower(entry.Fields["Workspace-ID"])
	if wid != session.WID.AsString() {
		session.SendQuickResponse(411, "BAD KEYCARD DATA", "Workspace doesn't match login")
		return
	}

	uid := strings.ToLower(entry.Fields["User-ID"])

	// admin, support, and abuse can't change their user IDs
	adminAddresses := []string{"admin", "support", "abuse"}
	for _, address := range adminAddresses {
		currentAddress := address + "/" + viper.GetString("global.domain")
		currentWid, err := dbhandler.ResolveAddress(currentAddress)
		if err != nil {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Writef("commandAddEntry: error resolving address: %s", err.Error())
			return
		}
		if session.WID.AsString() == currentWid {
			if uid != address {
				session.SendQuickResponse(411, "BAD KEYCARD DATA",
					"Admin, Support, and Abuse can't change their user IDs")
				return
			}
		}
	}

	adminAddress := "admin/" + viper.GetString("global.domain")
	adminWid, err := dbhandler.ResolveAddress(adminAddress)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandAddEntry: error resolving address: %s", err.Error())
		return
	}

	if session.WID.AsString() == adminWid {
		if uid != "admin" {
			session.SendQuickResponse(411, "BAD KEYCARD DATA", "Admin can't change its user ID")
			return
		}
	}

	// IsDataCompliant performs all of the checks we need to ensure that the data given to us by the
	// client EXCEPT checking the expiration
	var isExpired bool
	isExpired, err = entry.IsExpired()
	if err != nil {
		session.SendQuickResponse(411, "BAD KEYCARD DATA", err.Error())
		return
	}
	if isExpired {
		session.SendQuickResponse(412, "NONCOMPLIANT KEYCARD DATA", "Keycard entry is expired")
		return
	}

	if wid != session.WID.AsString() {
		session.SendQuickResponse(412, "NONCOMPLIANT KEYCARD DATA", "Workspace ID mismatch")
		return
	}

	// IsDataCompliant ensures that we actually have a string in the Index field that will convert
	// into a positive integer
	currentIndex, _ := strconv.Atoi(entry.Fields["Index"])

	// Passing a 0 as the start index means we'll get just the current entry
	tempStrList, err := dbhandler.GetUserEntries(wid, 0, 0)
	if err == nil {
		if len(tempStrList) == 0 {
			if currentIndex != 1 {
				session.SendQuickResponse(412, "NONCOMPLIANT KEYCARD DATA",
					"Root entry index must be 1")
				return
			}
		} else {
			prevEntry, err := keycard.NewEntryFromData(tempStrList[0])
			if err != nil {
				session.SendQuickResponse(300, "INTERNAL SERVER ERRROR", "")
				logging.Writef("ERROR AddEntry: previous keycard entry invalid for workspace %s",
					wid)
				return
			}

			prevIndex, _ := strconv.Atoi(prevEntry.Fields["Index"])
			if currentIndex != prevIndex+1 {
				session.SendQuickResponse(412, "NONCOMPLIANT KEYCARD DATA", "Non-sequential index")
				return
			}

			// If there are previous entries for the workspace, the chain of trust must be validated.
			isOK, err := entry.VerifyChain(prevEntry)
			if !isOK || err != nil {
				session.SendQuickResponse(412, "NONCOMPLIANT KEYCARD DATA",
					"Entry failed to chain verify")
				return
			}
		}
	}

	// If we managed to get this far, we can (theoretically) trust the initial data set given to us
	// by the client. Here we sign the data with the organization's signing key

	pskpair, err := dbhandler.GetPrimarySigningPair()
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERRROR", "")
		logging.Write("ERROR AddEntry: missing primary signing key in database.")
		return
	}

	// We bypass the nacl/sign module because it requires a 64-bit private key. We, however, pass
	// around the 32-bit ed25519 seeds used to generate the keys. Thus, we have to skip using
	// nacl.Sign() and go directly to the equivalent code in the ed25519 module.
	pskBytes := ed25519.NewKeyFromSeed(pskpair.PrivateKey.RawData())
	rawSignature := ed25519.Sign(pskBytes, entry.MakeByteString(-1))
	if rawSignature == nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERRROR", "")
		logging.Write("ERROR AddEntry: failed to org sign entry.")
		return
	}
	signature := "ED25519:" + b85.Encode(rawSignature)
	entry.Signatures["Organization"] = signature

	if currentIndex == 1 {
		tempStrList, err = dbhandler.GetOrgEntries(0, 0)
		if err != nil || len(tempStrList) == 0 {
			session.SendQuickResponse(300, "INTERNAL SERVER ERRROR", "")
			logging.Write("ERROR AddEntry: failed to obtain last org entry.")
			return
		}
		orgEntry, err := keycard.NewEntryFromData(tempStrList[0])
		if err != nil {
			session.SendQuickResponse(300, "INTERNAL SERVER ERRROR", "")
			logging.Write("ERROR AddEntry: failed to create entry from last org entry data.")
			return
		}
		entry.PrevHash = orgEntry.Hash
	} else {
		// tempStrList still contains the user's current entry data
		prevEntry, _ := keycard.NewEntryFromData(tempStrList[0])
		entry.PrevHash = prevEntry.Hash
	}

	err = entry.GenerateHash("BLAKE2B-256")
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERRROR", "")
		logging.Write("ERROR AddEntry: failed to hash entry.")
		return
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
	if request.Action == "CANCEL" {
		session.SendQuickResponse(200, "OK", "")
		return
	}
	if request.Action != "ADDENTRY" ||
		request.Validate([]string{"User-Signature"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing User-Signature field")
		return
	}

	entry.Signatures["User"] = request.Data["User-Signature"]
	if !entry.IsCompliant() {
		session.SendQuickResponse(412, "NONCOMPLIANT KEYCARD DATA", "")
		return
	}

	var crkey ezn.CryptoString
	err = crkey.Set(entry.Fields["Contact-Request-Verification-Key"])
	if err != nil {
		session.SendQuickResponse(413, "INVALID SIGNATURE", "Bad Contact-Request-Verification-Key")
		return
	}
	verified, err := entry.VerifySignature(crkey, "User")
	if err != nil || !verified {
		session.SendQuickResponse(413, "INVALID SIGNATURE", "User-Signature failed to verify")
		return
	}

	err = dbhandler.AddEntry(entry)
	if err == nil {
		session.SendQuickResponse(200, "OK", "")
	} else {
		session.SendQuickResponse(300, "INTERNAL SERVER ERRROR", "")
		logging.Write("ERROR AddEntry: failed to add entry.")
	}
}

func commandOrgCard(session *sessionState) {
	// command syntax:
	// ORGCARD(Start-Index, End-Index=0)

	if !session.Message.HasField("Start-Index") {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing Start-Index")
		return
	}

	var startIndex, endIndex int
	var err error
	startIndex, err = strconv.Atoi(session.Message.Data["Start-Index"])
	if err != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad Start-Index")
		return
	}

	if session.Message.HasField("End-Index") {
		endIndex, err = strconv.Atoi(session.Message.Data["End-Index"])
		if err != nil {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad End-Index")
			return
		}
	}

	entries, err := dbhandler.GetOrgEntries(startIndex, endIndex)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandOrgCard: error retrieving org entries: %s", err.Error())
		return
	}
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
		if err != nil {
			session.SendQuickResponse(400, "BAD REQUEST", "")
			return
		}
		if request.Action == "CANCEL" {
			return
		}
		if request.Action != "TRANSFER" {
			session.SendQuickResponse(400, "BAD REQUEST", "")
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
		session.SendQuickResponse(404, "NOT FOUND", "")
	}
}

func commandUserCard(session *sessionState) {
	// command syntax:
	// USERCARD(Owner, Start-Index, End-Index=0)

	if session.Message.Validate([]string{"Owner", "Start-Index"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing Start-Index")
		return
	}

	if dbhandler.GetMensagoAddressType(session.Message.Data["Owner"]) == 0 {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing Owner")
		return
	}

	wid, _ := dbhandler.ResolveAddress(session.Message.Data["Owner"])
	if wid == "" {
		session.SendQuickResponse(404, "NOT FOUND", "")
		return
	}

	var startIndex, endIndex int
	startIndex, err := strconv.Atoi(session.Message.Data["Start-Index"])
	if err != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad Start-Index")
		return
	}

	if session.Message.HasField("End-Index") {
		endIndex, err = strconv.Atoi(session.Message.Data["End-Index"])
		if err != nil {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad End-Index")
			return
		}
	}

	entries, err := dbhandler.GetUserEntries(wid, startIndex, endIndex)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandUserCard: error retrieving user entries: %s", err.Error())
		return
	}
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
		if err != nil {
			session.SendQuickResponse(400, "BAD REQUEST", "")
			return
		}
		if request.Action == "CANCEL" {
			return
		}
		if request.Action != "TRANSFER" {
			session.SendQuickResponse(400, "BAD REQUEST", "")
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
		session.SendQuickResponse(404, "NOT FOUND", "")
	}
}

func commandIsCurrent(session *sessionState) {
	// command syntax:
	// ISCURRENT(Index, Workspace-ID="")

	if !session.Message.HasField("Index") {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing Index")
		return
	}

	index, err := strconv.Atoi(session.Message.Data["Index"])
	if err != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad Index")
		return
	}

	var currentIndex int
	if session.Message.HasField("Workspace-ID") {
		wid := strings.ToLower(session.Message.Data["Workspace-ID"])
		if !dbhandler.ValidateUUID(wid) {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad Workspace-ID")
			return
		}

		entries, err := dbhandler.GetUserEntries(wid, 0, 0)
		if err != nil {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Writef("commandIsCurrent: error retrieving user %s entries: %s", wid,
				err.Error())
			return
		}

		entryCount := len(entries)
		if entryCount < 1 {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Writef("commandIsCurrent: no user entries found for %s", wid)
			return
		}

		orgentry, err := keycard.NewEntryFromData(entries[0])
		if err != nil {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Writef("commandIsCurrent: error creating user entry from data for %s: %s",
				wid, err.Error())
			return
		}

		currentIndex, err = strconv.Atoi(orgentry.Fields["Index"])
		if err != nil {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Writef("commandIsCurrent: bad index in user entry data for %s: %s",
				wid, err.Error())
			return
		}
	} else {
		entries, err := dbhandler.GetOrgEntries(0, 0)
		if err != nil {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Writef("commandIsCurrent: error retrieving org entries: %s", err.Error())
			return
		}

		entryCount := len(entries)
		if entryCount < 1 {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Writef("commandIsCurrent: no org entries found")
			return
		}

		orgentry, err := keycard.NewEntryFromData(entries[0])
		if err != nil {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Writef("commandIsCurrent: error creating org entry from data: %s", err.Error())
			return
		}

		currentIndex, err = strconv.Atoi(orgentry.Fields["Index"])
		if err != nil {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Writef("commandIsCurrent: bad index in org entry data: %s", err.Error())
			return
		}
	}

	response := NewServerResponse(200, "OK")
	if index == currentIndex {
		response.Data["Is-Current"] = "YES"
	} else {
		response.Data["Is-Current"] = "NO"
	}
	session.SendResponse(*response)
}

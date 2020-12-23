package main

import (
	"fmt"
	"strconv"

	"github.com/darkwyrm/anselusd/dbhandler"
	"github.com/darkwyrm/anselusd/keycard"
)

func commandAddEntry(session *sessionState) {
	// Command syntax:
	// ADDENTRY

	// Client sends the ADDENTRY command.
	// When the server is ready, the server responds with 100 CONTINUE.
	// The client uploads the data for entry, transmitting the entry data between the
	//	 ----- BEGIN USER KEYCARD ----- header and the ----- END USER KEYCARD ----- footer.
	// The server then checks compliance of the entry data. Assuming that it complies, the server
	//	 generates a cryptographic signature and responds with 100 CONTINUE, returning the
	//	 fingerprint of the data and the hash of the previous entry in the database.
	// The client verifies the signature against the organization’s verification key
	// The client appends the hash from the previous entry as the Previous-Hash field
	// The client generates the hash value for the entry as the Hash field
	// The client signs the entry as the User-Signature field and then uploads the result to the
	//	 server using the same header and footer as the first time.
	// Once uploaded, the server validates the Hash and User-Signature fields, and, assuming that
	//	 all is well, adds it to the keycard database and returns 200 OK.

	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED")
		return
	}

	session.SendStringResponse(100, "CONTINUE")

	request, err := session.GetRequest()

	// ReadClient can set the IsTerminating flag if the read times out
	if session.IsTerminating || (err != nil && err.Error() != "EOF") {
		return
	}

	if request.Validate([]string{"Base-Entry"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST")
	}

	// We've managed to read data from the client. Now for some extensive validation.
	var entry *keycard.Entry
	entry, err = keycard.NewEntryFromData(request.Data["Base-Entry"])

	if err != nil || !entry.IsDataCompliant() {
		session.SendStringResponse(411, "BAD KEYCARD DATA")
		return
	}

	// IsDataCompliant performs all of the checks we need to ensure that the data given to us by the
	// client EXCEPT checking the expiration
	var isExpired bool
	isExpired, err = entry.IsExpired()
	if err != nil || isExpired {
		session.SendStringResponse(411, "BAD KEYCARD DATA")
		return
	}

	// If we managed to get this far, we can (theoretically) trust the initial data set given to us
	// by the client. Here we sign the data with the organization's signing key

	// TODO: Finish implementing AddEntry()
}

func commandOrgCard(session *sessionState) {
	// command syntax:
	// ORGCARD(Start-Index, End-Index=0)

	if !session.Message.HasField("Start-Index") {
		session.SendStringResponse(400, "BAD REQUEST")
		return
	}

	var startIndex, endIndex int
	var err error
	startIndex, err = strconv.Atoi(session.Message.Data["Start-Index"])
	if err != nil {
		session.SendStringResponse(400, "BAD REQUEST")
		return
	}

	if session.Message.HasField("End-Index") {
		endIndex, err = strconv.Atoi(session.Message.Data["End-Index"])
		if err != nil {
			session.SendStringResponse(400, "BAD REQUEST")
			return
		}
	}

	entries, err := dbhandler.GetOrgEntries(startIndex, endIndex)
	entryCount := len(entries)
	if entryCount > 0 {
		for i, entry := range entries {
			var response ServerResponse
			response.Code = 102
			response.Status = "ITEM"
			response.Data["Index"] = fmt.Sprintf("%d", i+1)
			response.Data["Total"] = fmt.Sprintf("%d", entryCount)
			response.Data["Entry"] = entry

			if session.SendResponse(response) != nil {
				return
			}
		}
	} else {
		session.SendStringResponse(404, "NOT FOUND")
	}
}

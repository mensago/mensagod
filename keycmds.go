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
		session.WriteClient("401 UNAUTHORIZED\r\n")
		return
	}

	if len(session.Tokens) != 1 {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	session.WriteClient("100 CONTINUE\r\n")

	rawstr, err := session.ReadClient()

	// ReadClient can set the IsTerminating flag if the read times out
	if session.IsTerminating || (err != nil && err.Error() != "EOF") {
		return
	}

	// We've managed to read data from the client. Now for some extensive validation.
	var entry *keycard.Entry
	entry, err = keycard.NewEntryFromData(rawstr)

	if err != nil || !entry.IsDataCompliant() {
		session.WriteClient("411 BAD KEYCARD DATA\r\n")
		return
	}

	// IsDataCompliant performs all of the checks we need to ensure that the data given to us by the
	// client EXCEPT checking the expiration
	var isExpired bool
	isExpired, err = entry.IsExpired()
	if err != nil || isExpired {
		session.WriteClient("411 BAD KEYCARD DATA\r\n")
		return
	}

	// If we managed to get this far, we can (theoretically) trust the initial data set given to us
	// by the client. Here we sign the data with the organization's signing key

	// TODO: Finish implementing AddEntry()
}

func commandOrgCard(session *sessionState) {
	// command syntax:
	// ORGCARD start_index [end_index]

	var startIndex, endIndex int
	var err error
	switch len(session.Tokens) {
	case 2:
		startIndex, err = strconv.Atoi(session.Tokens[1])
		if err != nil {
			session.WriteClient("400 BAD REQUEST\r\n")
			return
		}
	case 3:
		startIndex, err = strconv.Atoi(session.Tokens[1])
		if err != nil {
			session.WriteClient("400 BAD REQUEST\r\n")
			return
		}
		endIndex, err = strconv.Atoi(session.Tokens[2])
		if err != nil {
			session.WriteClient("400 BAD REQUEST\r\n")
			return
		}
	default:
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}
	entries, err := dbhandler.GetOrgEntries(startIndex, endIndex)
	entryCount := len(entries)
	if entryCount > 0 {
		for i, entry := range entries {
			_, err = session.WriteClient(fmt.Sprintf("102 ITEM %d %d\r\n", i+1, entryCount))
			if err != nil {
				return
			}
			_, err = session.WriteClient("----- BEGIN ORG ENTRY -----\r\n" + entry +
				"----- END ORG ENTRY -----\r\n")
			if err != nil {
				return
			}
		}
	} else {
		session.WriteClient("404 NOT FOUND\r\n")
	}
}

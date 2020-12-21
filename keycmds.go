package main

import (
	"fmt"
	"strconv"

	"github.com/darkwyrm/anselusd/dbhandler"
)

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

package main

func commandOrgCard(session *sessionState) {
	// command syntax:
	// ORGCARD start_index [end_index]

	if len(session.Tokens) < 2 || len(session.Tokens) > 3 {
		session.WriteClient("400 BAD REQUEST\r\n")
		return
	}

	// TODO: Finish implementing commandOrgCard
}

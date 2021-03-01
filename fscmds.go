package main

import (
	"os"
	"path/filepath"

	"github.com/darkwyrm/anselusd/logging"
	"github.com/spf13/viper"
)

func commandCopy(session *sessionState) {
	// Command syntax:
	// COPY(FilePath, DestDir)

	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"Source", "DestDir"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	session.SendStringResponse(301, "NOT IMPLEMENTED", "")
}

func commandDelete(session *sessionState) {
	// Command syntax:
	// DELETE(FilePath)
	session.SendStringResponse(301, "NOT IMPLEMENTED", "")
}

func commandExists(session *sessionState) {
	// Command syntax:
	// EXISTS(Path)

	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	if !session.Message.HasField("Path") {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	fsPath := filepath.Join(viper.GetString("global.workspace_dir"), session.WID,
		session.Message.Data["Path"])
	_, err := os.Stat(fsPath)
	if err != nil {
		if os.IsNotExist(err) {
			session.SendStringResponse(404, "NOT FOUND", "")
		} else {
			session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Writef("commandExists: Filesystem error %s", err.Error())
		}
	} else {
		session.SendStringResponse(200, "OK", "")
	}
}

func commandInstallTemp(session *sessionState) {
	// Command syntax:
	// INSTALLTEMP(Name, Path)

	// TODO: Add to client-server spec
	session.SendStringResponse(301, "NOT IMPLEMENTED", "")
}

func commandList(session *sessionState) {
	// Command syntax:
	// LIST(Time=0)
	session.SendStringResponse(301, "NOT IMPLEMENTED", "")
}

func commandListDirs(session *sessionState) {
	// Command syntax:
	// LISTDIRS()

	// TODO: Add to client-server spec
	session.SendStringResponse(301, "NOT IMPLEMENTED", "")
}

func commandMkDir(session *sessionState) {
	// Command syntax:
	// MKDIR(Path)
	session.SendStringResponse(301, "NOT IMPLEMENTED", "")
}

func commandMkTemp(session *sessionState) {
	// Command syntax:
	// MKTEMP(Path)

	// TODO: Add to client-server spec
	session.SendStringResponse(301, "NOT IMPLEMENTED", "")
}

func commandMove(session *sessionState) {
	// Command syntax:
	// MOVE(FilePath, DestDir)
	session.SendStringResponse(301, "NOT IMPLEMENTED", "")
}

func commandRmDir(session *sessionState) {
	// Command syntax:
	// RMDIR(Path)

	// TODO: Add to client-server spec
	session.SendStringResponse(301, "NOT IMPLEMENTED", "")
}

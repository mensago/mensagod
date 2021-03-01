package main

import (
	"os"
	"path/filepath"

	"github.com/darkwyrm/anselusd/fshandler"
	"github.com/darkwyrm/anselusd/logging"
	"github.com/spf13/viper"
)

func handleFSError(session *sessionState, err error) {
	if os.IsNotExist(err) {
		session.SendStringResponse(404, "NOT FOUND", "")
		return
	}
	if os.IsExist(err) {
		session.SendStringResponse(408, "RESOURCE EXISTS", "")
		return
	}
	if os.IsPermission(err) {
		session.SendStringResponse(403, "FORBIDDEN", "")
		return
	}
	session.SendStringResponse(400, "BAD REQUEST", err.Error())
}

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

	fsh := fshandler.GetFSHandler()
	exists, err := fsh.Exists(session.Message.Data["Source"])
	if err != nil {
		handleFSError(session, err)
		return
	}
	if !exists {
		session.SendStringResponse(404, "NOT FOUND", "Source does not exist")
	}

	exists, err = fsh.Exists(session.Message.Data["DestDir"])
	if err != nil {
		handleFSError(session, err)
		return
	}
	if !exists {
		session.SendStringResponse(404, "NOT FOUND", "Destination does not exist")
	}

	newName, err := fsh.CopyFile(session.Message.Data["Source"], session.Message.Data["DestDir"])
	if err != nil {
		handleFSError(session, err)
		return
	}

	response := NewServerResponse(200, "OK")
	response.Data["NewName"] = newName
	session.SendResponse(*response)
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

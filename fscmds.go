package main

import (
	"os"
	"strconv"
	"strings"

	"github.com/darkwyrm/mensagod/fshandler"
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
	// COPY(SourceFile, DestDir)

	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"SourceFile", "DestDir"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	fsh := fshandler.GetFSHandler()
	exists, err := fsh.Exists(session.Message.Data["SourceFile"])
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

	newName, err := fsh.CopyFile(session.Message.Data["SourceFile"],
		session.Message.Data["DestDir"])
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
	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"Path"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	fsh := fshandler.GetFSHandler()
	err := fsh.DeleteFile(session.Message.Data["Path"])
	if err != nil {
		handleFSError(session, err)
		return
	}

	session.SendStringResponse(200, "OK", "")
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

	fsh := fshandler.GetFSHandler()
	exists, err := fsh.Exists(session.Message.Data["Path"])
	if err != nil {
		handleFSError(session, err)
		return
	}

	if exists {
		session.SendStringResponse(200, "OK", "")
	} else {
		session.SendStringResponse(404, "NOT FOUND", "")
	}
}

func commandList(session *sessionState) {
	// Command syntax:
	// LIST(Time=0)
	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"Path"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	var err error
	var unixTime int64 = 0
	if session.Message.HasField("Time") {
		unixTime, err = strconv.ParseInt(session.Message.Data["Time"], 10, 64)
		if err != nil {
			session.SendStringResponse(400, "BAD REQUEST", "Bad time field")
		}
		return
	}

	fsh := fshandler.GetFSHandler()
	names, err := fsh.ListFiles(session.Message.Data["Path"], int64(unixTime))
	if err != nil {
		handleFSError(session, err)
		return
	}

	response := NewServerResponse(200, "OK")
	response.Data["Files"] = strings.Join(names, ",")
	session.SendResponse(*response)
}

func commandListDirs(session *sessionState) {
	// Command syntax:
	// LISTDIRS()

	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	fsh := fshandler.GetFSHandler()
	names, err := fsh.ListDirectories(session.CurrentPath.MensagoPath())
	if err != nil {
		handleFSError(session, err)
		return
	}

	response := NewServerResponse(200, "OK")
	response.Data["Directories"] = strings.Join(names, ",")
	session.SendResponse(*response)
}

func commandMkDir(session *sessionState) {
	// Command syntax:
	// MKDIR(Path)
	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"Path"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	fsh := fshandler.GetFSHandler()
	err := fsh.MakeDirectory(session.Message.Data["Path"])
	if err != nil {
		handleFSError(session, err)
		return
	}

	session.SendStringResponse(200, "OK", "")
}

func commandMove(session *sessionState) {
	// Command syntax:
	// MOVE(SourceFile, DestDir)

	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"SourceFile", "DestDir"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	fsh := fshandler.GetFSHandler()
	exists, err := fsh.Exists(session.Message.Data["SourceFile"])
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

	err = fsh.MoveFile(session.Message.Data["SourceFile"], session.Message.Data["DestDir"])
	if err != nil {
		handleFSError(session, err)
		return
	}

	session.SendStringResponse(200, "OK", "")
}

func commandRmDir(session *sessionState) {
	// Command syntax:
	// RMDIR(Path, Recursive)
	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"Path", "Recursive"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	fsh := fshandler.GetFSHandler()
	exists, err := fsh.Exists(session.Message.Data["Path"])
	if err != nil {
		handleFSError(session, err)
		return
	}
	if !exists {
		session.SendStringResponse(404, "NOT FOUND", "Path does not exist")
	}

	recurseStr := strings.ToLower(session.Message.Data["Recursive"])
	var recursive bool
	if recurseStr == "true" || recurseStr == "yes" {
		recursive = true
	}
	err = fsh.RemoveDirectory(session.Message.Data["Path"], recursive)
	if err != nil {
		handleFSError(session, err)
		return
	}

	session.SendStringResponse(200, "OK", "")
}

func commandSelect(session *sessionState) {
	// Command syntax:
	// SELECT(Path)

	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	if !session.Message.HasField("Path") {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	fsh := fshandler.GetFSHandler()
	path, err := fsh.Select(session.Message.Data["Path"])
	if err != nil {
		handleFSError(session, err)
	}
	session.CurrentPath = path
}

func commandUpload(session *sessionState) {
	// Command syntax:
	// UPLOAD(Size,Hash,Name="",Offset=0)

	// if session.LoginState != loginClientSession {
	// 	session.SendStringResponse(401, "UNAUTHORIZED", "")
	// 	return
	// }

	// if session.Message.Validate([]string{"Size", "Hash"}) != nil {
	// 	session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
	// 	return
	// }

	// // Both Name and Hash must be present when resuming
	// if (session.Message.HasField("Name") && !session.Message.HasField("Hash")) ||
	// 	(session.Message.HasField("Hash") && !session.Message.HasField("Name")) {
	// 	session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
	// 	return
	// }

	// var fileSize int64
	// var fileHash cs.CryptoString
	// err := fileHash.Set(session.Message.Data["Hash"])
	// if err != nil {
	// 	session.SendStringResponse(400, "BAD REQUEST", err.Error())
	// }

	// fileSize, err = strconv.ParseInt(session.Message.Data["Size"], 10, 64)
	// if err != nil {
	// 	session.SendStringResponse(400, "BAD REQUEST", "Bad file size")
	// }

	// var resumeName string
	// var resumeOffset int64
	// if session.Message.HasField("Name") {
	// 	if !fshandler.ValidateTempFileName(session.Message.Data["Name"]) {
	// 		session.SendStringResponse(400, "BAD REQUEST", "Bad file name")
	// 	}

	// 	resumeName = session.Message.Data["Name"]

	// 	resumeOffset, err = strconv.ParseInt(session.Message.Data["Offset"], 10, 64)
	// 	if err != nil {
	// 		session.SendStringResponse(400, "BAD REQUEST", "Bad offset")
	// 	}
	// }

	session.SendStringResponse(308, "UNIMPLEMENTED", "")
}

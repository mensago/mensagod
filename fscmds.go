package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	cs "github.com/darkwyrm/mensagod/cryptostring"
	"github.com/darkwyrm/mensagod/dbhandler"
	"github.com/darkwyrm/mensagod/fshandler"
	"github.com/darkwyrm/mensagod/logging"
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
	// COPY(SourceFile, DestDir)

	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"SourceFile", "DestDir"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	fsh := fshandler.GetFSProvider()
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

	fsh := fshandler.GetFSProvider()
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

	fsh := fshandler.GetFSProvider()
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

func commandGetQuotaInfo(session *sessionState) {
	// Command syntax:
	// GETQUOTAINFO(Workspace='')

	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	quotaSize, err := strconv.ParseInt(session.Message.Data["Size"], 10, 64)
	if err != nil || quotaSize < 1 {
		session.SendStringResponse(400, "BAD REQUEST", "Bad quota size")
		return
	}

	adminAddress := "admin/" + viper.GetString("global.domain")
	adminWid, err := dbhandler.ResolveAddress(adminAddress)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandGetQuotaInfo: Error resolving admin address: %s", err)
		return
	}

	isAdmin := adminWid == session.WID

	if session.Message.HasField("Workspaces") {
		if !isAdmin {
			session.SendStringResponse(403, "FORBIDDEN", "Only admin can use the Workspaces field")
			return
		}

		widList := strings.Split(session.Message.Data["Workspaces"], ",")
		if len(widList) > 100 {
			session.SendStringResponse(414, "LIMIT REACHED", "No more than 100 workspaces at once")
		}

		quotaList := make([]string, len(widList))
		usageList := make([]string, len(widList))
		for i, rawwid := range widList {
			wid := strings.TrimSpace(rawwid)
			if !dbhandler.ValidateUUID(wid) {
				session.SendStringResponse(400, "BAD REQUEST", "Bad workspace ID "+wid)
				return
			}

			u, q, err := dbhandler.GetQuotaInfo(wid)
			if err != nil {
				session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
				logging.Writef("commandGetQuotaInfo: Error getting quota info for workspace %s: %s",
					wid, err)
				return
			}
			usageList[i] = fmt.Sprintf("%d", u)
			quotaList[i] = fmt.Sprintf("%d", q)
		}

		response := NewServerResponse(200, "OK")
		response.Data["DiskUsage"] = strings.Join(usageList, ",")
		response.Data["QuotaSize"] = strings.Join(quotaList, ",")
		session.SendResponse(*response)
		return
	}

	u, q, err := dbhandler.GetQuotaInfo(session.WID)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandGetQuotaInfo: Error getting quota info for workspace %s: %s",
			session.WID, err)
		return
	}

	response := NewServerResponse(200, "OK")
	response.Data["DiskUsage"] = fmt.Sprintf("%d", u)
	response.Data["QuotaSize"] = fmt.Sprintf("%d", q)
	session.SendResponse(*response)
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

	fsh := fshandler.GetFSProvider()
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

	fsh := fshandler.GetFSProvider()
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

	fsh := fshandler.GetFSProvider()
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

	fsh := fshandler.GetFSProvider()
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

	fsh := fshandler.GetFSProvider()
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

	fsh := fshandler.GetFSProvider()
	path, err := fsh.Select(session.Message.Data["Path"])
	if err != nil {
		handleFSError(session, err)
	}
	session.CurrentPath = path
}

func commandSetQuota(session *sessionState) {
	// Command syntax:
	// SETQUOTA(Workspaces, Size)

	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"Workspaces", "Size"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	quotaSize, err := strconv.ParseInt(session.Message.Data["Size"], 10, 64)
	if err != nil || quotaSize < 1 {
		session.SendStringResponse(400, "BAD REQUEST", "Bad quota size")
		return
	}

	adminAddress := "admin/" + viper.GetString("global.domain")
	adminWid, err := dbhandler.ResolveAddress(adminAddress)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandSetQuota: Error resolving admin address: %s", err)
		return
	}

	if session.LoginState != loginClientSession || session.WID != adminWid {
		session.SendStringResponse(403, "FORBIDDEN", "Only admin can use this")
		return
	}

	// If an error occurs processing one workspace, no further processing is made for reasons of
	// both security and simplicity
	workspaces := strings.Split(session.Message.Data["Workspaces"], ",")
	for _, rawWID := range workspaces {
		w := strings.TrimSpace(rawWID)
		if !dbhandler.ValidateUUID(w) {
			session.SendStringResponse(400, "BAD REQUEST", fmt.Sprintf("Bad workspace ID %s", w))
			return
		}

		err = dbhandler.SetQuota(w, uint64(quotaSize))
		if err != nil {
			session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
			return
		}
	}

	session.SendStringResponse(200, "OK", "")
}

func commandUpload(session *sessionState) {
	// Command syntax:
	// UPLOAD(Size,Hash,Name="",Offset=0)

	if session.LoginState != loginClientSession {
		session.SendStringResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"Size", "Hash", "Path"}) != nil {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	// Both Name and Hash must be present when resuming
	if (session.Message.HasField("TempName") && !session.Message.HasField("Offset")) ||
		(session.Message.HasField("Offset") && !session.Message.HasField("TempName")) {
		session.SendStringResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	var fileSize int64
	var fileHash cs.CryptoString
	err := fileHash.Set(session.Message.Data["Hash"])
	if err != nil {
		session.SendStringResponse(400, "BAD REQUEST", err.Error())
		return
	}

	fileSize, err = strconv.ParseInt(session.Message.Data["Size"], 10, 64)
	if err != nil || fileSize < 1 {
		session.SendStringResponse(400, "BAD REQUEST", "Bad file size")
		return
	}

	fsp := fshandler.GetFSProvider()
	exists, err := fsp.Exists(session.Message.Data["Path"])
	if err != nil {
		if err == fshandler.ErrBadPath {
			session.SendStringResponse(400, "BAD REQUEST", "Bad file path")
		} else {
			session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		}
		return
	}
	if !exists {
		session.SendStringResponse(404, "NOT FOUND", "")
		return
	}

	// var resumeName string
	// var resumeOffset int64
	// if session.Message.HasField("Name") {
	// 	if !fshandler.ValidateTempFileName(session.Message.Data["Name"]) {
	// 		session.SendStringResponse(400, "BAD REQUEST", "Bad file name")
	// 		return
	// 	}

	// 	resumeName = session.Message.Data["Name"]

	// 	resumeOffset, err = strconv.ParseInt(session.Message.Data["Offset"], 10, 64)
	// 	if err != nil {
	// 		session.SendStringResponse(400, "BAD REQUEST", "Bad offset")
	// 		return
	// 	}
	// }

	// An administrator can dictate how large a file can be stored on the server

	if fileSize > int64(viper.GetInt("global.max_file_size"))*0x10_0000 {
		session.SendStringResponse(414, "LIMIT REACHED", "")
		return
	}

	// Arguments have been validated, do a quota check

	diskUsage, diskQuota, err := dbhandler.GetQuotaInfo(session.WID)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	if diskQuota != 0 && uint64(fileSize)+diskUsage > diskQuota {
		session.SendStringResponse(409, "QUOTA INSUFFICIENT", "")
		return
	}

	tempHandle, tempName, err := fsp.MakeTempFile(session.WID)
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	response := NewServerResponse(100, "CONTINUE")
	response.Data["TempName"] = tempName
	session.SendResponse(*response)

	bytesRead, err := session.ReadFileData(uint64(fileSize), tempHandle)
	tempHandle.Close()
	if err != nil {
		response = NewServerResponse(305, "INTERRUPTED")
		response.Data["Offset"] = fmt.Sprintf("%d", bytesRead)
		session.SendResponse(*response)
		return
	}

	hashMatch, err := fshandler.HashFile(strings.Join([]string{"/ tmp", session.WID, tempName}, " "),
		fileHash)
	if err != nil {
		if err == cs.ErrUnsupportedAlgorithm {
			session.SendStringResponse(309, "UNSUPPORTED ALGORITHM", "")
		} else {
			session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		}
		return
	}
	if !hashMatch {
		fsp.DeleteTempFile(session.WID, tempName)
		session.SendStringResponse(410, "HASH MISMATCH", "")
		return
	}

	realName, err := fsp.InstallTempFile(session.WID, tempName, session.Message.Data["Path"])
	if err != nil {
		session.SendStringResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	response = NewServerResponse(200, "OK")
	response.Data["FileName"] = realName
	session.SendResponse(*response)
}

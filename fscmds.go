package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	cs "github.com/darkwyrm/mensagod/cryptostring"
	"github.com/darkwyrm/mensagod/dbhandler"
	"github.com/darkwyrm/mensagod/fshandler"
	"github.com/darkwyrm/mensagod/logging"
	"github.com/darkwyrm/mensagod/misc"
	"github.com/spf13/viper"
)

func handleFSError(session *sessionState, err error) {
	if os.IsNotExist(err) {
		session.SendQuickResponse(404, "NOT FOUND", "")
		return
	}
	if os.IsExist(err) {
		session.SendQuickResponse(408, "RESOURCE EXISTS", "")
		return
	}
	if os.IsPermission(err) {
		session.SendQuickResponse(403, "FORBIDDEN", "")
		return
	}
	session.SendQuickResponse(400, "BAD REQUEST", err.Error())
}

func commandCopy(session *sessionState) {
	// Command syntax:
	// COPY(SourceFile, DestDir)

	if session.LoginState != loginClientSession {
		session.SendQuickResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"SourceFile", "DestDir"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	fsh := fshandler.GetFSProvider()
	exists, err := fsh.Exists(session.Message.Data["SourceFile"])
	if err != nil {
		handleFSError(session, err)
		return
	}
	if !exists {
		session.SendQuickResponse(404, "NOT FOUND", "Source does not exist")
		return
	}

	exists, err = fsh.Exists(session.Message.Data["DestDir"])
	if err != nil {
		handleFSError(session, err)
		return
	}
	if !exists {
		session.SendQuickResponse(404, "NOT FOUND", "Destination does not exist")
		return
	}

	// Arguments have been validated, do a quota check
	parts := strings.Split(session.Message.Data["SourceFile"], " ")

	if !fshandler.ValidateFileName(parts[len(parts)-1]) {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad source path")
		return
	}

	nameparts := strings.Split(parts[len(parts)-1], ".")
	fileSize, err := strconv.ParseInt(nameparts[1], 10, 64)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	diskUsage, diskQuota, err := dbhandler.GetQuotaInfo(session.WID)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	if diskQuota != 0 && uint64(fileSize)+diskUsage > diskQuota {
		session.SendQuickResponse(409, "QUOTA INSUFFICIENT", "")
		return
	}

	newName, err := fsh.CopyFile(session.Message.Data["SourceFile"],
		session.Message.Data["DestDir"])
	if err != nil {
		handleFSError(session, err)
		return
	}

	dbhandler.AddSyncRecord(session.WID, dbhandler.UpdateRecord{
		Type: dbhandler.UpdateAdd,
		Data: session.Message.Data["DestDir"] + " " + newName,
		Time: time.Now().UTC().Unix(),
	})

	response := NewServerResponse(200, "OK")
	response.Data["NewName"] = newName
	session.SendResponse(*response)
}

func commandDelete(session *sessionState) {
	// Command syntax:
	// DELETE(FilePath)
	if session.LoginState != loginClientSession {
		session.SendQuickResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"Path"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	fsh := fshandler.GetFSProvider()
	err := fsh.DeleteFile(session.Message.Data["Path"])
	if err != nil {
		handleFSError(session, err)
		return
	}

	dbhandler.AddSyncRecord(session.WID, dbhandler.UpdateRecord{
		Type: dbhandler.UpdateDelete,
		Data: session.Message.Data["Path"],
		Time: time.Now().UTC().Unix(),
	})
	session.SendQuickResponse(200, "OK", "")
}

func commandDownload(session *sessionState) {
	// Command syntax:
	// DOWNLOAD(Path,Offset=0)

	if session.LoginState != loginClientSession {
		session.SendQuickResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"Path"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	fsp := fshandler.GetFSProvider()
	exists, err := fsp.Exists(session.Message.Data["Path"])
	if err != nil {
		if err == misc.ErrBadPath {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad file path")
		} else {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		}
		return
	}
	if !exists {
		session.SendQuickResponse(404, "NOT FOUND", "")
		return
	}

	var resumeOffset int64
	if session.Message.HasField("Offset") {
		resumeOffset, err = strconv.ParseInt(session.Message.Data["Offset"], 10, 64)
		if err != nil || resumeOffset < 1 {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad resume offset")
			return
		}

		fileSize, err := fsp.GetFileSize(session.Message.Data["Path"])
		if err != nil {
			handleFSError(session, err)
			return
		}

		if resumeOffset > fileSize {
			session.SendQuickResponse(400, "BAD REQUEST", "Resume offset greater than file size")
			return
		}
	}

	// Check permissions. Users can download from an individual workspace only if it is their own
	// or from multiuser workspaces if they have the appropriate permissions. Until multiuser
	// workspaces are implemented, we can make this check pretty simple.
	if !strings.HasPrefix(session.Message.Data["Path"], "/ "+session.WID) {
		session.SendQuickResponse(403, "FORBIDDEN", "Can only download from your own workspace")
		return
	}

	pathParts := strings.Split(session.Message.Data["Path"], " ")
	filename := pathParts[len(pathParts)-1]
	if !fshandler.ValidateFileName(filename) {
		session.SendQuickResponse(400, "BAD REQUEST", "Path is not a file")
		return
	}
	filenameParts := strings.Split(filename, ".")
	if len(filenameParts) != 3 {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	response := NewServerResponse(100, "CONTINUE")
	response.Data["Size"] = filenameParts[1]
	session.SendResponse(*response)

	request, err := session.GetRequest()
	if err != nil && err.Error() != "EOF" {
		return
	}
	session.Message = request

	if request.Action == "CANCEL" {
		return
	}

	if request.Action != "DOWNLOAD" || !request.HasField("Size") ||
		request.Data["Size"] != filenameParts[1] {
		session.SendQuickResponse(400, "BAD REQUEST", "File size confirmation mismatch")
		return
	}

	_, err = session.SendFileData(session.Message.Data["Path"], resumeOffset)
	if err != nil {
		handleFSError(session, err)
		return
	}
}

func commandExists(session *sessionState) {
	// Command syntax:
	// EXISTS(Path)

	if session.LoginState != loginClientSession {
		session.SendQuickResponse(401, "UNAUTHORIZED", "")
		return
	}

	if !session.Message.HasField("Path") {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	fsh := fshandler.GetFSProvider()
	exists, err := fsh.Exists(session.Message.Data["Path"])
	if err != nil {
		handleFSError(session, err)
		return
	}

	if exists {
		session.SendQuickResponse(200, "OK", "")
	} else {
		session.SendQuickResponse(404, "NOT FOUND", "")
	}
}

func commandGetQuotaInfo(session *sessionState) {
	// Command syntax:
	// GETQUOTAINFO(Workspace='')

	if session.LoginState != loginClientSession {
		session.SendQuickResponse(401, "UNAUTHORIZED", "")
		return
	}

	adminAddress := "admin/" + viper.GetString("global.domain")
	adminWid, err := dbhandler.ResolveAddress(adminAddress)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandGetQuotaInfo: Error resolving admin address: %s", err)
		return
	}

	isAdmin := adminWid == session.WID

	if session.Message.HasField("Workspaces") {
		if !isAdmin {
			session.SendQuickResponse(403, "FORBIDDEN", "Only admin can use the Workspaces field")
			return
		}

		widList := strings.Split(session.Message.Data["Workspaces"], ",")
		if len(widList) > 100 {
			session.SendQuickResponse(414, "LIMIT REACHED", "No more than 100 workspaces at once")
		}

		quotaList := make([]string, len(widList))
		usageList := make([]string, len(widList))
		for i, rawwid := range widList {
			wid := strings.TrimSpace(rawwid)
			if !dbhandler.ValidateUUID(wid) {
				session.SendQuickResponse(400, "BAD REQUEST", "Bad workspace ID "+wid)
				return
			}

			u, q, err := dbhandler.GetQuotaInfo(wid)
			if err != nil {
				session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
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
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
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
		session.SendQuickResponse(401, "UNAUTHORIZED", "")
		return
	}

	listPath := session.CurrentPath.MensagoPath()
	if session.Message.HasField("Path") {
		listPath = session.Message.Data["Path"]
	}

	var err error
	var unixTime int64 = 0
	if session.Message.HasField("Time") {
		unixTime, err = strconv.ParseInt(session.Message.Data["Time"], 10, 64)
		if err != nil {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad time field")
			return
		}
	}

	fsh := fshandler.GetFSProvider()
	names, err := fsh.ListFiles(listPath, int64(unixTime))
	if err != nil {
		handleFSError(session, err)
		return
	}

	if len(names) > 0 {
		fileNames := make([]string, len(names))
		for i, name := range names {
			fileNames[i] = `"` + name + `"`
		}
		responseString := `{"Code":200,"Status":"OK","Info":"","Data":{"Files":[` +
			strings.Join(fileNames, ",") + `]}}`
		session.WriteClient(responseString)
	} else {
		session.WriteClient(`{"Code":200,"Status":"OK","Info":"","Data":{"Files":[]}}`)
	}
}

func commandListDirs(session *sessionState) {
	// Command syntax:
	// LISTDIRS(path)

	if session.LoginState != loginClientSession {
		session.SendQuickResponse(401, "UNAUTHORIZED", "")
		return
	}

	listPath := session.CurrentPath.MensagoPath()
	if session.Message.HasField("Path") {
		listPath = session.Message.Data["Path"]
	}

	fsh := fshandler.GetFSProvider()
	names, err := fsh.ListDirectories(listPath)
	if err != nil {
		handleFSError(session, err)
		return
	}

	if len(names) > 0 {
		fileNames := make([]string, len(names))
		for i, name := range names {
			fileNames[i] = `"` + name + `"`
		}
		responseString := `{"Code":200,"Status":"OK","Info":"","Data":{"Directories":[` +
			strings.Join(fileNames, ",") + `]}}`
		session.WriteClient(responseString)
	} else {
		session.WriteClient(`{"Code":200,"Status":"OK","Info":"","Data":{"Directories":[]}}`)
	}
}

func commandMkDir(session *sessionState) {
	// Command syntax:
	// MKDIR(Path)
	if session.LoginState != loginClientSession {
		session.SendQuickResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"Path"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	fsh := fshandler.GetFSProvider()
	err := fsh.MakeDirectory(session.Message.Data["Path"])
	if err != nil {
		handleFSError(session, err)
		return
	}

	dbhandler.AddSyncRecord(session.WID, dbhandler.UpdateRecord{
		Type: dbhandler.UpdateAdd,
		Data: session.Message.Data["Path"],
		Time: time.Now().UTC().Unix(),
	})
	session.SendQuickResponse(200, "OK", "")
}

func commandMove(session *sessionState) {
	// Command syntax:
	// MOVE(SourceFile, DestDir)

	if session.LoginState != loginClientSession {
		session.SendQuickResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"SourceFile", "DestDir"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	fsh := fshandler.GetFSProvider()
	exists, err := fsh.Exists(session.Message.Data["SourceFile"])
	if err != nil {
		handleFSError(session, err)
		return
	}
	if !exists {
		session.SendQuickResponse(404, "NOT FOUND", "Source does not exist")
		return
	}

	exists, err = fsh.Exists(session.Message.Data["DestDir"])
	if err != nil {
		handleFSError(session, err)
		return
	}
	if !exists {
		session.SendQuickResponse(404, "NOT FOUND", "Destination does not exist")
		return
	}

	err = fsh.MoveFile(session.Message.Data["SourceFile"], session.Message.Data["DestDir"])
	if err != nil {
		handleFSError(session, err)
		return
	}

	dbhandler.AddSyncRecord(session.WID, dbhandler.UpdateRecord{
		Type: dbhandler.UpdateMove,
		Data: session.Message.Data["SourceFile"] + " " + session.Message.Data["DestDir"],
		Time: time.Now().UTC().Unix(),
	})
	session.SendQuickResponse(200, "OK", "")
}

func commandRmDir(session *sessionState) {
	// Command syntax:
	// RMDIR(Path, Recursive)
	if session.LoginState != loginClientSession {
		session.SendQuickResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"Path", "Recursive"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	fsh := fshandler.GetFSProvider()
	exists, err := fsh.Exists(session.Message.Data["Path"])
	if err != nil {
		handleFSError(session, err)
		return
	}
	if !exists {
		session.SendQuickResponse(404, "NOT FOUND", "Path does not exist")
		return
	}

	recurseStr := strings.ToLower(session.Message.Data["Recursive"])
	var recursive bool
	if recurseStr == "true" || recurseStr == "yes" {
		recursive = true
	}

	usage, err := fsh.GetDiskUsage(session.Message.Data["Path"])
	if err != nil {
		handleFSError(session, err)
		return
	}

	err = fsh.RemoveDirectory(session.Message.Data["Path"], recursive)
	if err != nil {
		handleFSError(session, err)
		return
	}
	dbhandler.ModifyQuotaUsage(session.WID, int64(usage)*-1)

	dbhandler.AddSyncRecord(session.WID, dbhandler.UpdateRecord{
		Type: dbhandler.UpdateDelete,
		Data: session.Message.Data["Path"],
		Time: time.Now().UTC().Unix(),
	})
	session.SendQuickResponse(200, "OK", "")
}

func commandSelect(session *sessionState) {
	// Command syntax:
	// SELECT(Path)

	if session.LoginState != loginClientSession {
		session.SendQuickResponse(401, "UNAUTHORIZED", "")
		return
	}

	if !session.Message.HasField("Path") {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	fsh := fshandler.GetFSProvider()
	path, err := fsh.Select(session.Message.Data["Path"])
	if err != nil {
		handleFSError(session, err)
		return
	}
	session.CurrentPath = path

	session.SendQuickResponse(200, "OK", "")
}

func commandSetQuota(session *sessionState) {
	// Command syntax:
	// SETQUOTA(Workspaces, Size)

	if session.LoginState != loginClientSession {
		session.SendQuickResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"Workspaces", "Size"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	quotaSize, err := strconv.ParseInt(session.Message.Data["Size"], 10, 64)
	if err != nil || quotaSize < 1 {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad quota size")
		return
	}

	adminAddress := "admin/" + viper.GetString("global.domain")
	adminWid, err := dbhandler.ResolveAddress(adminAddress)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandSetQuota: Error resolving admin address: %s", err)
		return
	}

	if session.LoginState != loginClientSession || session.WID != adminWid {
		session.SendQuickResponse(403, "FORBIDDEN", "Only admin can use this")
		return
	}

	// If an error occurs processing one workspace, no further processing is made for reasons of
	// both security and simplicity
	workspaces := strings.Split(session.Message.Data["Workspaces"], ",")
	for _, rawWID := range workspaces {
		w := strings.TrimSpace(rawWID)
		if !dbhandler.ValidateUUID(w) {
			session.SendQuickResponse(400, "BAD REQUEST", fmt.Sprintf("Bad workspace ID %s", w))
			return
		}

		err = dbhandler.SetQuota(w, uint64(quotaSize))
		if err != nil {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			return
		}
	}

	session.SendQuickResponse(200, "OK", "")
}

func commandUpload(session *sessionState) {
	// Command syntax:
	// UPLOAD(Size,Hash,Path,Name="",Offset=0)

	if session.LoginState != loginClientSession {
		session.SendQuickResponse(401, "UNAUTHORIZED", "")
		return
	}

	if session.Message.Validate([]string{"Size", "Hash", "Path"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	// Both Name and Hash must be present when resuming
	if (session.Message.HasField("TempName") && !session.Message.HasField("Offset")) ||
		(session.Message.HasField("Offset") && !session.Message.HasField("TempName")) {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	var fileSize int64
	var fileHash cs.CryptoString
	err := fileHash.Set(session.Message.Data["Hash"])
	if err != nil {
		session.SendQuickResponse(400, "BAD REQUEST", err.Error())
		return
	}

	fileSize, err = strconv.ParseInt(session.Message.Data["Size"], 10, 64)
	if err != nil || fileSize < 1 {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad file size")
		return
	}

	fsp := fshandler.GetFSProvider()
	exists, err := fsp.Exists(session.Message.Data["Path"])
	if err != nil {
		if err == misc.ErrBadPath {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad file path")
		} else {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		}
		return
	}
	if !exists {
		session.SendQuickResponse(404, "NOT FOUND", "")
		return
	}

	var resumeOffset int64
	if session.Message.HasField("TempName") {
		if !fshandler.ValidateTempFileName(session.Message.Data["TempName"]) {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad file name")
			return
		}

		resumeOffset, err = strconv.ParseInt(session.Message.Data["Offset"], 10, 64)
		if err != nil || resumeOffset < 1 {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad resume offset")
			return
		}

		if resumeOffset > fileSize {
			session.SendQuickResponse(400, "BAD REQUEST", "Resume offset greater than file size")
			return
		}
	}

	// An administrator can dictate how large a file can be stored on the server

	if fileSize > int64(viper.GetInt("performance.max_file_size"))*0x10_0000 {
		session.SendQuickResponse(414, "LIMIT REACHED", "")
		return
	}

	// Arguments have been validated, do a quota check

	diskUsage, diskQuota, err := dbhandler.GetQuotaInfo(session.WID)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	if diskQuota != 0 && uint64(fileSize)+diskUsage > diskQuota {
		session.SendQuickResponse(409, "QUOTA INSUFFICIENT", "")
		return
	}

	var tempHandle *os.File
	var tempName string
	if resumeOffset > 0 {
		tempName = session.Message.Data["TempName"]
		tempHandle, err = fsp.OpenTempFile(session.WID, tempName, resumeOffset)

		if err != nil {
			session.SendQuickResponse(400, "BAD REQUEST", err.Error())
			return
		}

	} else {
		tempHandle, tempName, err = fsp.MakeTempFile(session.WID)
		if err != nil {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			return
		}
	}

	response := NewServerResponse(100, "CONTINUE")
	response.Data["TempName"] = tempName
	session.SendResponse(*response)

	if resumeOffset > 0 {
		_, err = session.ReadFileData(uint64(fileSize-resumeOffset), tempHandle)
	} else {
		_, err = session.ReadFileData(uint64(fileSize), tempHandle)
	}
	tempHandle.Close()
	if err != nil {
		// Transfer was interrupted. We won't delete the file--we will leave it so the client can
		// attempt to resume the upload later.
		return
	}

	hashMatch, err := fshandler.HashFile(strings.Join([]string{"/ tmp", session.WID, tempName}, " "),
		fileHash)
	if err != nil {
		if err == cs.ErrUnsupportedAlgorithm {
			session.SendQuickResponse(309, "UNSUPPORTED ALGORITHM", "")
		} else {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		}
		return
	}
	if !hashMatch {
		fsp.DeleteTempFile(session.WID, tempName)
		session.SendQuickResponse(410, "HASH MISMATCH", "")
		return
	}

	realName, err := fsp.InstallTempFile(session.WID, tempName, session.Message.Data["Path"])
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	dbhandler.ModifyQuotaUsage(session.WID, fileSize)
	dbhandler.AddSyncRecord(session.WID, dbhandler.UpdateRecord{
		Type: dbhandler.UpdateAdd,
		Data: session.Message.Data["Path"],
		Time: time.Now().UTC().Unix(),
	})

	response = NewServerResponse(200, "OK")
	response.Data["FileName"] = realName
	session.SendResponse(*response)
}

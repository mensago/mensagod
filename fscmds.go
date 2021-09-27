package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	ezn "github.com/darkwyrm/goeznacl"
	"github.com/darkwyrm/mensagod/dbhandler"
	"github.com/darkwyrm/mensagod/fshandler"
	"github.com/darkwyrm/mensagod/logging"
	"github.com/darkwyrm/mensagod/misc"
	"github.com/google/uuid"
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
	sourcePath := strings.ToLower(session.Message.Data["SourceFile"])
	exists, err := fsh.Exists(sourcePath)
	if err != nil {
		handleFSError(session, err)
		return
	}
	if !exists {
		session.SendQuickResponse(404, "NOT FOUND", "Source does not exist")
		return
	}

	destPath := strings.ToLower(session.Message.Data["DestDir"])
	exists, err = fsh.Exists(destPath)
	if err != nil {
		handleFSError(session, err)
		return
	}
	if !exists {
		session.SendQuickResponse(404, "NOT FOUND", "Destination does not exist")
		return
	}

	// Arguments have been validated, do a quota check
	parts := strings.Split(sourcePath, " ")

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

	diskUsage, diskQuota, err := dbhandler.GetQuotaInfo(session.WID.AsString())
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	if diskQuota != 0 && uint64(fileSize)+diskUsage > diskQuota {
		session.SendQuickResponse(409, "QUOTA INSUFFICIENT", "")
		return
	}

	newName, err := fsh.CopyFile(sourcePath, destPath)
	if err != nil {
		handleFSError(session, err)
		return
	}

	dbhandler.AddSyncRecord(session.WID.AsString(), dbhandler.UpdateRecord{
		ID:   uuid.NewString(),
		Type: dbhandler.UpdateAdd,
		Data: destPath + " " + newName,
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

	deletePath := strings.ToLower(session.Message.Data["Path"])
	fsh := fshandler.GetFSProvider()
	err := fsh.DeleteFile(deletePath)
	if err != nil {
		handleFSError(session, err)
		return
	}

	dbhandler.AddSyncRecord(session.WID.AsString(), dbhandler.UpdateRecord{
		ID:   uuid.NewString(),
		Type: dbhandler.UpdateDelete,
		Data: deletePath,
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

	downloadPath := session.Message.Data["Path"]
	fsp := fshandler.GetFSProvider()
	exists, err := fsp.Exists(downloadPath)
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

		fileSize, err := fsp.GetFileSize(downloadPath)
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
	if !strings.HasPrefix(downloadPath, "/ wsp "+session.WID.AsString()) {
		session.SendQuickResponse(403, "FORBIDDEN", "Can only download from your own workspace")
		return
	}

	pathParts := strings.Split(downloadPath, " ")
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

	_, err = session.SendFileData(downloadPath, resumeOffset)
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

	existsPath := strings.ToLower(session.Message.Data["Path"])
	fsh := fshandler.GetFSProvider()
	exists, err := fsh.Exists(existsPath)
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

	isAdmin := adminWid == session.WID.AsString()

	if session.Message.HasField("Workspaces") {
		if !isAdmin {
			session.SendQuickResponse(403, "FORBIDDEN", "Only admin can use the Workspaces field")
			return
		}

		widList := strings.Split(strings.ToLower(session.Message.Data["Workspaces"]), ",")
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

	u, q, err := dbhandler.GetQuotaInfo(session.WID.AsString())
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		logging.Writef("commandGetQuotaInfo: Error getting quota info for workspace %s: %s",
			session.WID.AsString(), err)
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
		listPath = strings.ToLower(session.Message.Data["Path"])

		switch {
		case listPath == "/ wsp":
		case strings.HasPrefix(listPath, "/ tmp"):
		case listPath == "/ out":
			session.SendQuickResponse(401, "UNAUTHORIZED", "")
			return
		}
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
		listPath = strings.ToLower(session.Message.Data["Path"])

		switch {
		case listPath == "/ wsp":
		case strings.HasPrefix(listPath, "/ tmp"):
		case listPath == "/ out":
			session.SendQuickResponse(401, "UNAUTHORIZED", "")
			return
		}
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

	dirPath := strings.ToLower(session.Message.Data["Path"])
	fsh := fshandler.GetFSProvider()
	err := fsh.MakeDirectory(dirPath)
	if err != nil {
		handleFSError(session, err)
		return
	}

	dbhandler.AddSyncRecord(session.WID.AsString(), dbhandler.UpdateRecord{
		ID:   uuid.NewString(),
		Type: dbhandler.UpdateAdd,
		Data: dirPath,
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

	sourcePath := strings.ToLower(session.Message.Data["SourceFile"])
	fsh := fshandler.GetFSProvider()
	exists, err := fsh.Exists(sourcePath)
	if err != nil {
		handleFSError(session, err)
		return
	}
	if !exists {
		session.SendQuickResponse(404, "NOT FOUND", "Source does not exist")
		return
	}

	destPath := strings.ToLower(session.Message.Data["DestDir"])
	exists, err = fsh.Exists(destPath)
	if err != nil {
		handleFSError(session, err)
		return
	}
	if !exists {
		session.SendQuickResponse(404, "NOT FOUND", "Destination does not exist")
		return
	}

	err = fsh.MoveFile(sourcePath, destPath)
	if err != nil {
		handleFSError(session, err)
		return
	}

	dbhandler.AddSyncRecord(session.WID.AsString(), dbhandler.UpdateRecord{
		ID:   uuid.NewString(),
		Type: dbhandler.UpdateMove,
		Data: sourcePath + " " + destPath,
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

	dirPath := strings.ToLower(session.Message.Data["Path"])
	fsh := fshandler.GetFSProvider()
	exists, err := fsh.Exists(dirPath)
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

	usage, err := fsh.GetDiskUsage(dirPath)
	if err != nil {
		handleFSError(session, err)
		return
	}

	err = fsh.RemoveDirectory(dirPath, recursive)
	if err != nil {
		handleFSError(session, err)
		return
	}
	dbhandler.ModifyQuotaUsage(session.WID.AsString(), int64(usage)*-1)

	dbhandler.AddSyncRecord(session.WID.AsString(), dbhandler.UpdateRecord{
		ID:   uuid.NewString(),
		Type: dbhandler.UpdateDelete,
		Data: dirPath,
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

	selectPath := session.Message.Data["Path"]
	fsh := fshandler.GetFSProvider()
	path, err := fsh.Select(selectPath)
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

	if session.LoginState != loginClientSession || session.WID.AsString() != adminWid {
		session.SendQuickResponse(403, "FORBIDDEN", "Only admin can use this")
		return
	}

	// If an error occurs processing one workspace, no further processing is made for reasons of
	// both security and simplicity
	workspaces := strings.Split(strings.ToLower(session.Message.Data["Workspaces"]), ",")
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
	var fileHash ezn.CryptoString
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

	filePath := strings.ToLower(session.Message.Data["Path"])
	fsp := fshandler.GetFSProvider()
	exists, err := fsp.Exists(filePath)
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

	diskUsage, diskQuota, err := dbhandler.GetQuotaInfo(session.WID.AsString())
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
		tempHandle, err = fsp.OpenTempFile(session.WID.AsString(), tempName, resumeOffset)

		if err != nil {
			session.SendQuickResponse(400, "BAD REQUEST", err.Error())
			return
		}

	} else {
		tempHandle, tempName, err = fsp.MakeTempFile(session.WID.AsString())
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

	hashMatch, err := fshandler.HashFile(strings.Join([]string{"/ tmp", session.WID.AsString(),
		tempName}, " "), fileHash)
	if err != nil {
		if err == ezn.ErrUnsupportedAlgorithm {
			session.SendQuickResponse(309, "UNSUPPORTED ALGORITHM", "")
		} else {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		}
		return
	}
	if !hashMatch {
		fsp.DeleteTempFile(session.WID.AsString(), tempName)
		session.SendQuickResponse(410, "HASH MISMATCH", "")
		return
	}

	realName, err := fsp.InstallTempFile(session.WID.AsString(), tempName, filePath)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	dbhandler.ModifyQuotaUsage(session.WID.AsString(), fileSize)
	dbhandler.AddSyncRecord(session.WID.AsString(), dbhandler.UpdateRecord{
		ID:   uuid.NewString(),
		Type: dbhandler.UpdateAdd,
		Data: filePath,
		Time: time.Now().UTC().Unix(),
	})

	response = NewServerResponse(200, "OK")
	response.Data["FileName"] = realName
	session.SendResponse(*response)
}

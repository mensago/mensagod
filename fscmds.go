package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	ezn "gitlab.com/darkwyrm/goeznacl"
	"gitlab.com/mensago/mensagod/dbhandler"
	"gitlab.com/mensago/mensagod/fshandler"
	"gitlab.com/mensago/mensagod/logging"
	"gitlab.com/mensago/mensagod/misc"
	"gitlab.com/mensago/mensagod/types"
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

	if !session.RequireLogin() {
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
	filename := parts[len(parts)-1]

	if !fshandler.ValidateFileName(filename) {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad source path")
		return
	}

	nameparts := strings.Split(filename, ".")
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

	fshandler.RLockFile(filename)
	newName, err := fsh.CopyFile(sourcePath, destPath)
	fshandler.RUnlockFile(filename)
	if err != nil {
		handleFSError(session, err)
		return
	}

	dbhandler.AddSyncRecord(session.WID.AsString(), dbhandler.UpdateRecord{
		ID:   uuid.NewString(),
		Type: dbhandler.UpdateCreate,
		Data: destPath + " " + newName,
		Time: time.Now().UTC().Unix(),
	})

	response := NewServerResponse(200, "OK")
	response.Data["NewName"] = newName
	session.SendResponse(*response)
}

func commandDelete(session *sessionState) {
	// Command syntax:
	// DELETE(PathCount, Path0[, Path1...])
	if !session.RequireLogin() {
		return
	}

	if session.Message.Validate([]string{"PathCount", "Path0"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	pathCount, err := strconv.Atoi(session.Message.Data["PathCount"])
	if err != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "PathCount missing or bad value")
		return
	}

	for i := 0; i < pathCount; i++ {
		fieldName := fmt.Sprintf("Path%d", i)
		_, ok := session.Message.Data[fieldName]
		if !ok {
			session.SendQuickResponse(400, "BAD REQUEST", "Message missing field "+fieldName)
			return
		}

		deletePath := strings.TrimSpace(strings.ToLower(session.Message.Data[fieldName]))
		parts := strings.Split(deletePath, " ")
		filename := parts[len(parts)-1]

		fsh := fshandler.GetFSProvider()
		fshandler.LockFile(filename)
		err := fsh.DeleteFile(deletePath)
		fshandler.UnlockFile(filename)
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
	}

	session.SendQuickResponse(200, "OK", "")
}

func commandDownload(session *sessionState) {
	// Command syntax:
	// DOWNLOAD(Path,Offset=0)

	if !session.RequireLogin() {
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

	fshandler.RLockFile(filename)
	_, err = session.SendFileData(downloadPath, resumeOffset)
	fshandler.RUnlockFile(filename)
	if err != nil {
		handleFSError(session, err)
		return
	}
}

func commandExists(session *sessionState) {
	// Command syntax:
	// EXISTS(Path)

	if !session.RequireLogin() {
		return
	}

	if !session.Message.HasField("Path") {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	existsPath := strings.ToLower(session.Message.Data["Path"])
	pathParts := strings.Split(existsPath, " ")
	filename := pathParts[len(pathParts)-1]

	fsh := fshandler.GetFSProvider()
	fshandler.RLockFile(filename)
	exists, err := fsh.Exists(existsPath)
	fshandler.RUnlockFile(filename)
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

	if !session.RequireLogin() {
		return
	}

	isAdmin, err := session.IsAdmin()
	if err != nil {
		return
	}

	if session.Message.HasField("Workspace-ID") {
		widStr := strings.ToLower(session.Message.Data["Workspace-ID"])
		if widStr != string(session.WID) && !isAdmin {
			session.SendQuickResponse(403, "FORBIDDEN",
				"No permission to access quota info of other workspaces")
			return
		}

		wid := types.ToUUID(widStr)
		if !wid.IsValid() {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad workspace ID "+wid.AsString())
			return
		}

		u, q, err := dbhandler.GetQuotaInfo(wid)
		if err != nil {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
			logging.Writef("commandGetQuotaInfo: Error getting quota info for workspace %s: %s",
				wid, err)
			return
		}

		response := NewServerResponse(200, "OK")
		response.Data["DiskUsage"] = fmt.Sprintf("%d", u)
		response.Data["QuotaSize"] = fmt.Sprintf("%d", q)
		session.SendResponse(*response)
		return
	}

	u, q, err := dbhandler.GetQuotaInfo(session.WID)
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
	if !session.RequireLogin() {
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

	response := NewServerResponse(200, "OK")
	if len(names) > 0 {
		response.Data["Files"] = strings.Join(names, ",")
	} else {
		response.Data["Files"] = ""
	}
	session.SendResponse(*response)
}

func commandListDirs(session *sessionState) {
	// Command syntax:
	// LISTDIRS(path)

	if !session.RequireLogin() {
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
	if !session.RequireLogin() {
		return
	}

	if session.Message.Validate([]string{"Path", "ClientPath"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	clientPath := ezn.NewCS(session.Message.Data["ClientPath"])
	if !clientPath.IsValid() {
		session.SendQuickResponse(400, "BAD REQUEST", "Client path missing or bad value")
		return
	}

	dirPath := strings.ToLower(session.Message.Data["Path"])
	fsh := fshandler.GetFSProvider()
	err := fsh.MakeDirectory(dirPath)
	if err != nil {
		handleFSError(session, err)
		return
	}

	err = dbhandler.AddFolderEntry(session.WID, dirPath, clientPath)
	if err != nil {
		fsh.RemoveDirectory(dirPath, false)
		if errors.Is(err, misc.ErrExists) {
			session.SendQuickResponse(408, "RESOURCE EXISTS", "")
		} else {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "commandMkDir.1")
		}
		return
	}

	dbhandler.AddSyncRecord(session.WID.AsString(), dbhandler.UpdateRecord{
		ID:   uuid.NewString(),
		Type: dbhandler.UpdateMkDir,
		Data: dirPath + " " + clientPath.AsString(),
		Time: time.Now().UTC().Unix(),
	})
	session.SendQuickResponse(200, "OK", "")
}

func commandMove(session *sessionState) {
	// Command syntax:
	// MOVE(SourceFile, DestDir)

	if !session.RequireLogin() {
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

	pathParts := strings.Split(sourcePath, " ")
	filename := pathParts[len(pathParts)-1]

	fshandler.LockFile(filename)
	err = fsh.MoveFile(sourcePath, destPath)
	fshandler.UnlockFile(filename)
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

func commandReplace(session *sessionState) {
	// Command syntax:
	// REPLACE(OldPath, NewPath, Size,Hash,Name="",Offset=0)

	if !session.RequireLogin() {
		return
	}

	if session.Message.Validate([]string{"Size", "Hash", "OldPath", "NewPath"}) != nil {
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

	filePath := strings.ToLower(session.Message.Data["OldPath"])
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
		session.SendQuickResponse(404, "NOT FOUND", "OldPath doesn't exist.")
		return
	}

	newFilePath := strings.ToLower(session.Message.Data["NewPath"])
	exists, err = fsp.Exists(newFilePath)
	if err != nil {
		if err == misc.ErrBadPath {
			session.SendQuickResponse(400, "BAD REQUEST", "Bad file path")
		} else {
			session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		}
		return
	}
	if !exists {
		session.SendQuickResponse(404, "NOT FOUND", "NewPath doesn't exist.")
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

	realName, err := fsp.InstallTempFile(session.WID.AsString(), tempName, newFilePath)
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	parts := strings.Split(filePath, " ")
	filename := parts[len(parts)-1]

	fshandler.LockFile(filename)
	err = fsp.DeleteFile(filePath)
	fshandler.UnlockFile(filename)
	if err != nil {
		handleFSError(session, err)
		return
	}

	dbhandler.AddSyncRecord(session.WID.AsString(), dbhandler.UpdateRecord{
		ID:   uuid.NewString(),
		Type: dbhandler.UpdateReplace,
		Data: strings.ToLower(filePath + " " + newFilePath),
		Time: time.Now().UTC().Unix(),
	})

	response = NewServerResponse(200, "OK")
	response.Data["FileName"] = realName
	session.SendResponse(*response)
}

func commandRmDir(session *sessionState) {
	// Command syntax:
	// RMDIR(Path)
	if !session.RequireLogin() {
		return
	}

	if session.Message.Validate([]string{"Path"}) != nil {
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

	usage, err := fsh.GetDiskUsage(dirPath)
	if err != nil {
		handleFSError(session, err)
		return
	}

	// Although called LockFile, it just uses string identifiers, so we can lock folders, too. :)
	fshandler.LockFile(dirPath)
	err = fsh.RemoveDirectory(dirPath, false)
	fshandler.UnlockFile(dirPath)
	if err != nil {
		handleFSError(session, err)
		return
	}
	dbhandler.ModifyQuotaUsage(session.WID, int64(usage)*-1)

	dbhandler.AddSyncRecord(session.WID.AsString(), dbhandler.UpdateRecord{
		ID:   uuid.NewString(),
		Type: dbhandler.UpdateRmDir,
		Data: dirPath,
		Time: time.Now().UTC().Unix(),
	})
	session.SendQuickResponse(200, "OK", "")
}

func commandSelect(session *sessionState) {
	// Command syntax:
	// SELECT(Path)

	if !session.RequireLogin() {
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
	// SETQUOTA(Workspace, Size)

	if !session.RequireLogin() {
		return
	}

	if session.Message.Validate([]string{"Workspace", "Size"}) != nil {
		session.SendQuickResponse(400, "BAD REQUEST", "Missing required field")
		return
	}

	quotaSize, err := strconv.ParseInt(session.Message.Data["Size"], 10, 64)
	if err != nil || quotaSize < 1 {
		session.SendQuickResponse(400, "BAD REQUEST", "Bad quota size")
		return
	}

	isAdmin, err := session.IsAdmin()
	if err != nil || !isAdmin {
		// IsAdmin() handles notifying the client, too. :)
		return
	}

	// If an error occurs processing one workspace, no further processing is made for reasons of
	// both security and simplicity
	wid := types.ToUUID(strings.ToLower(session.Message.Data["Workspace"]))
	if !wid.IsValid() {
		session.SendQuickResponse(400, "BAD REQUEST", fmt.Sprintf("Bad workspace ID "+
			wid.AsString()))
		return
	}

	if wid == session.WID {
		session.SendQuickResponse(403, "FORBIDDEN", "admin accounts may not have quotas")
		return
	}

	err = dbhandler.SetQuota(wid, uint64(quotaSize))
	if err != nil {
		session.SendQuickResponse(300, "INTERNAL SERVER ERROR", "")
		return
	}

	session.SendQuickResponse(200, "OK", "")
}

func commandUpload(session *sessionState) {
	// Command syntax:
	// UPLOAD(Size,Hash,Path,Name="",Offset=0)

	if !session.RequireLogin() {
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

	dbhandler.ModifyQuotaUsage(session.WID, fileSize)
	dbhandler.AddSyncRecord(session.WID.AsString(), dbhandler.UpdateRecord{
		ID:   uuid.NewString(),
		Type: dbhandler.UpdateCreate,
		Data: filePath,
		Time: time.Now().UTC().Unix(),
	})

	response = NewServerResponse(200, "OK")
	response.Data["FileName"] = realName
	session.SendResponse(*response)
}

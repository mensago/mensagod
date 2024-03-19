package mensagod.handlers

import keznacl.hash
import keznacl.hashFile
import libkeycard.RandomID
import libmensago.ClientRequest
import libmensago.MServerPath
import libmensago.ServerResponse
import mensagod.*
import mensagod.dbcmds.setQuota
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import testsupport.*
import java.net.InetAddress
import java.net.Socket
import java.nio.file.Paths
import java.time.Instant
import java.util.*
import kotlin.io.path.exists

class FSCmdTest {

    @Test
    fun downloadTest() {
        val setupData = setupTest("handlers.download")
        ServerConfig.load().getOrThrow()
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        // Test Case #1: Successful file download
        val adminTopPath = Paths.get(setupData.testPath, "topdir", "wsp", adminWID.toString())
        adminTopPath.toFile().mkdirs()
        val devid = RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
        val fileInfo = makeTestFile(adminTopPath.toString(), fileSize = 1024)
        val testFilePath = Paths.get(adminTopPath.toString(), fileInfo.first)
        val fileHash = hashFile(testFilePath.toString()).getOrThrow()

        CommandTest(
            "download.1",
            SessionState(
                ClientRequest(
                    "DOWNLOAD", mutableMapOf(
                        "Path" to "/ wsp $adminWID ${fileInfo.first}",
                    )
                ), adminWID, LoginState.LoggedIn, devid
            ), ::commandDownload
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(100)
            response.assertField("Size") { it == "1024" }

            ClientRequest(
                "DOWNLOAD", mutableMapOf(
                    "Path" to "/ wsp $adminWID ${fileInfo.first}",
                    "Size" to response.data["Size"]!!,
                )
            ).send(socket.getOutputStream())

            val buffer = ByteArray(response.data["Size"]!!.toInt())
            val istream = socket.getInputStream()
            val bytesRead = istream.read(buffer)
            assertEquals(1024, bytesRead)

            val dataHash = hash(buffer).getOrThrow()
            assertEquals(fileHash, dataHash)
        }.run()

        // Test Case #2: Successful resume
        CommandTest(
            "download.2",
            SessionState(
                ClientRequest(
                    "DOWNLOAD", mutableMapOf(
                        "Path" to "/ wsp $adminWID ${fileInfo.first}",
                        "Offset" to "512",
                    )
                ), adminWID, LoginState.LoggedIn, devid
            ), ::commandDownload
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(100)
            response.assertField("Size") { it == "1024" }

            ClientRequest(
                "DOWNLOAD", mutableMapOf(
                    "Path" to "/ wsp $adminWID ${fileInfo.first}",
                    "Size" to response.data["Size"]!!,
                )
            ).send(socket.getOutputStream())

            val buffer = ByteArray(response.data["Size"]!!.toInt())
            val istream = socket.getInputStream()
            val bytesRead = istream.read(buffer)
            assertEquals(512, bytesRead)
            assertEquals("0".repeat(512), buffer.copyOf(bytesRead).decodeToString())
        }.run()
    }

    @Test
    fun existsTest() {
        val setupData = setupTest("handlers.exists")
        ServerConfig.load().getOrThrow()
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        // Test Case #1: Non-existent directory
        CommandTest(
            "exists.1",
            SessionState(
                ClientRequest("EXISTS", mutableMapOf("Path" to "/ wsp $adminWID")),
                adminWID,
                LoginState.LoggedIn,
                RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
            ), ::commandExists
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(404)
        }.run()

        // Test Case #2: Success
        val adminTopPath = Paths.get(setupData.testPath, "topdir", "wsp", adminWID.toString())
        adminTopPath.toFile().mkdirs()
        CommandTest(
            "exists.2",
            SessionState(
                ClientRequest("EXISTS", mutableMapOf("Path" to "/ wsp $adminWID")),
                adminWID,
                LoginState.LoggedIn,
                RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
            ), ::commandExists
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(200)
        }.run()
    }

    @Test
    fun listTest() {
        val setupData = setupTest("handlers.list")
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val adminTopPath = Paths.get(setupData.testPath, "topdir", "wsp", adminWID.toString())
        adminTopPath.toFile().mkdirs()

        val oneInfo = makeTestFile(
            adminTopPath.toString(),
            "1000000.1024.11111111-1111-1111-1111-111111111111",
            1024
        )
        val twoInfo = makeTestFile(
            adminTopPath.toString(),
            "1000100.1024.22222222-2222-2222-2222-222222222222",
            1024
        )
        val threeInfo = makeTestFile(
            adminTopPath.toString(),
            "1000200.1024.33333333-3333-3333-3333-333333333333",
            1024
        )

        // Test Case #1: Success
        CommandTest(
            "list.1",
            SessionState(
                ClientRequest("LIST").attach("Path", "/ wsp $adminWID"),
                adminWID, LoginState.LoggedIn,
            ), ::commandList
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
            assert(response.data.containsKey("FileCount"))
            assertEquals("3", response.data["FileCount"])
            assert(response.data.containsKey("Files"))
            val fileNames = response.data["Files"]!!.split(",")
            assertEquals(3, fileNames.size)
            assertEquals(oneInfo.first, fileNames[0])
            assertEquals(twoInfo.first, fileNames[1])
            assertEquals(threeInfo.first, fileNames[2])
        }.run()

        // Test Case #2: Success, time specified
        CommandTest(
            "list.2",
            SessionState(
                ClientRequest("LIST")
                    .attach("Path", "/ wsp $adminWID")
                    .attach("Time", "1000050"),
                adminWID, LoginState.LoggedIn,
            ), ::commandList
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
            assert(response.data.containsKey("FileCount"))
            assertEquals("2", response.data["FileCount"])
            assert(response.data.containsKey("Files"))
            val fileNames = response.data["Files"]!!.split(",")
            assertEquals(2, fileNames.size)
            assertEquals(twoInfo.first, fileNames[0])
            assertEquals(threeInfo.first, fileNames[1])
        }.run()

        // Test #3: Forbidden
        val userWID = RandomID.fromString(USER_PROFILE_DATA["wid"])!!
        CommandTest(
            "list.3",
            SessionState(
                ClientRequest("LIST")
                    .attach("Path", "/ wsp $adminWID"),
                userWID, LoginState.LoggedIn,
            ), ::commandList
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(403)
        }.run()

        // Test Case #4: Lots of files
        val userTopPath = Paths.get(setupData.testPath, "topdir", "wsp", userWID.toString())
        userTopPath.toFile().mkdirs()

        // This test has worked under Linux Mint for up to 500k files
        val fileCount = 2000
        repeat(fileCount) {
            makeTestFile(
                userTopPath.toString(),
                "${10_000_000_000 + it}.10_000_000_000.11111111-1111-1111-1111-111111111111",
                1024
            )
        }
        CommandTest(
            "list.4",
            SessionState(
                ClientRequest("LIST").attach("Path", "/ wsp $userWID"),
                adminWID, LoginState.LoggedIn,
            ), ::commandList
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
            assert(response.data.containsKey("Files"))
            assert(response.data.containsKey("FileCount"))
            val fileNames = response.data["Files"]!!.split(",")
            assertEquals(fileCount, fileNames.size)
        }.run()

        // Test Case #5: No files / no path specified
        val emptyWID = RandomID.fromString("7d80a092-6328-4661-99a8-0b48bd98a21c")!!
        val emptyTopPath = Paths.get(setupData.testPath, "topdir", "wsp", emptyWID.toString())
        emptyTopPath.toFile().mkdirs()
        CommandTest(
            "list.5",
            SessionState(
                ClientRequest("LIST"),
                adminWID, LoginState.LoggedIn,
                currentPath = MServerPath("/ wsp $emptyWID")
            ), ::commandList
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
            assert(response.data.containsKey("FileCount"))
            assertEquals("0", response.data["FileCount"])
            assert(!response.data.containsKey("Files"))
        }.run()
    }

    @Test
    fun listDirsTest() {
        val setupData = setupTest("handlers.listDirs")
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val adminTopPath = Paths.get(setupData.testPath, "topdir", "wsp", adminWID.toString())
        adminTopPath.toFile().mkdirs()
        val adminSubdirs = listOf(
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333"
        )
        adminSubdirs.forEach {
            Paths.get(setupData.testPath, "topdir", "wsp", adminWID.toString(), it)
                .toFile().mkdir()
        }

        // Test Case #1: Success
        CommandTest(
            "listDirs.1",
            SessionState(
                ClientRequest("LISTDIRS").attach("Path", "/ wsp $adminWID"),
                adminWID, LoginState.LoggedIn,
            ), ::commandListDirs
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
            assert(response.data.containsKey("DirectoryCount"))
            assertEquals("3", response.data["DirectoryCount"])
            assert(response.data.containsKey("Directories"))
            val dirNames = response.data["Directories"]!!.split(",")
            assertEquals(3, dirNames.size)
            adminSubdirs.forEachIndexed { i, item ->
                assertEquals(item, dirNames[i])
            }
        }.run()

        // Test #2: Forbidden
        val userWID = RandomID.fromString(USER_PROFILE_DATA["wid"])!!
        CommandTest(
            "listDirs.2",
            SessionState(
                ClientRequest("LISTDIRS")
                    .attach("Path", "/ wsp $adminWID"),
                userWID, LoginState.LoggedIn,
            ), ::commandListDirs
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(403)
        }.run()

        // Test Case #3: No subdirectories / no path specified
        val emptyWID = RandomID.fromString("7d80a092-6328-4661-99a8-0b48bd98a21c")!!
        val emptyTopPath = Paths.get(setupData.testPath, "topdir", "wsp", emptyWID.toString())
        emptyTopPath.toFile().mkdirs()
        CommandTest(
            "listDirs.3",
            SessionState(
                ClientRequest("LISTDIRS"),
                adminWID, LoginState.LoggedIn, null, false,
                MServerPath("/ wsp $emptyWID")
            ), ::commandListDirs
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
            assert(response.data.containsKey("DirectoryCount"))
            assertEquals("0", response.data["DirectoryCount"])
            assert(!response.data.containsKey("Directories"))
        }.run()
    }

    @Test
    fun mkDirTest() {
        val setupData = setupTest("handlers.mkDir")
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val adminTopPath = Paths.get(setupData.testPath, "topdir", "wsp", adminWID.toString())
        adminTopPath.toFile().mkdirs()

        // Test Case #1: Success
        CommandTest(
            "mkdir.1",
            SessionState(
                ClientRequest(
                    "MKDIR", mutableMapOf(
                        "Path" to "/ wsp $adminWID 11111111-1111-1111-1111-111111111111",
                        "ClientPath" to "XSALSA20:abcdefg"
                    )
                ), adminWID,
                LoginState.LoggedIn,
                RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
            ), ::commandMkDir
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(200)
        }.run()

        // Test Case #2: Missing parent directory
        CommandTest(
            "mkdir.2",
            SessionState(
                ClientRequest(
                    "MKDIR", mutableMapOf(
                        "Path" to "/ wsp b59b015d-e432-47b0-8457-416696615157 " +
                                "11111111-1111-1111-1111-111111111111",
                        "ClientPath" to "XSALSA20:abcdefg"
                    )
                ), adminWID,
                LoginState.LoggedIn,
                RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
            ), ::commandMkDir
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(404)
        }.run()
    }

    @Test
    fun rmdirTest() {
        setupTest("handlers.rmDir")
        ServerConfig.load().getOrThrow()
        val db = DBConn()
        setupUser(db)

        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val userWID = RandomID.fromString(USER_PROFILE_DATA["wid"])!!

        val lfs = LocalFS.get()
        val adminTop = lfs.entry(MServerPath("/ wsp $adminWID"))
        adminTop.makeDirectory()?.let { throw it }

        // Test Case #1: Missing parent directory
        CommandTest(
            "rmdir.1",
            SessionState(
                ClientRequest(
                    "RMDIR", mutableMapOf(
                        "Path" to "/ wsp b59b015d-e432-47b0-8457-416696615157 " +
                                "11111111-1111-1111-1111-111111111111",
                        "ClientPath" to "XSALSA20:abcdefg"
                    )
                ), adminWID,
                LoginState.LoggedIn,
                RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
            ), ::commandRmDir
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(404)
        }.run()

        val adminEntry = lfs.entry(
            MServerPath(
                "/ wsp $adminWID " +
                        "11111111-1111-1111-1111-111111111111"
            )
        )
        adminEntry.makeDirectory()?.let { throw it }

        // Test Case #2: Unauthorized
        CommandTest(
            "rmdir.2",
            SessionState(
                ClientRequest(
                    "RMDIR", mutableMapOf(
                        "Path" to "/ wsp $adminWID 11111111-1111-1111-1111-111111111111",
                    )
                ), userWID,
                LoginState.LoggedIn,
                RandomID.fromString(USER_PROFILE_DATA["devid"])!!
            ), ::commandRmDir
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(403)
        }.run()

        // Test Case #3: Success
        CommandTest(
            "rmdir.3",
            SessionState(
                ClientRequest(
                    "RMDIR", mutableMapOf(
                        "Path" to "/ wsp $adminWID 11111111-1111-1111-1111-111111111111",
                    )
                ), adminWID,
                LoginState.LoggedIn,
                RandomID.fromString(USER_PROFILE_DATA["devid"])!!
            ), ::commandRmDir
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()

            response.assertReturnCode(200)
            assertFalse(adminEntry.exists().getOrThrow())
        }.run()
    }

    @Test
    fun selectTest() {
        setupTest("handlers.select")
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!
        val userWID = RandomID.fromString(USER_PROFILE_DATA["wid"])!!

        val adminDir = MServerPath("/ wsp $adminWID").toHandle()
        adminDir.makeDirectory()?.let { throw it }
        val userDir = MServerPath("/ wsp $userWID").toHandle()
        userDir.makeDirectory()?.let { throw it }

        // Test Case #1: Success
        CommandTest(
            "select.1",
            SessionState(
                ClientRequest("SELECT").attach("Path", "/ wsp $adminWID"),
                adminWID, LoginState.LoggedIn,
            ), ::commandSelect
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            ServerResponse.receive(socket.getInputStream()).getOrThrow().assertReturnCode(200)
        }.run()

        // Test Case #2: Reject unauthorized access
        CommandTest(
            "select.2",
            SessionState(
                ClientRequest("SELECT").attach("Path", "/ wsp $adminWID"),
                userWID, LoginState.LoggedIn,
            ), ::commandSelect
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            ServerResponse.receive(socket.getInputStream()).getOrThrow().assertReturnCode(403)
        }.run()

        // Test Case #3: Reject non-existent path
        val noWID = RandomID.fromString("a402f0fc-156e-4c31-9a1c-06d567c3a9b7")
        CommandTest(
            "select.1",
            SessionState(
                ClientRequest("SELECT").attach("Path", "/ wsp $noWID"),
                adminWID, LoginState.LoggedIn,
            ), ::commandSelect
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            ServerResponse.receive(socket.getInputStream()).getOrThrow().assertReturnCode(404)
        }.run()
    }

    @Test
    fun uploadTest() {
        val setupData = setupTest("handlers.upload")
        ServerConfig.load().getOrThrow()
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        // Test Case #1: Successful file upload
        val adminTopPath = Paths.get(setupData.testPath, "topdir", "wsp", adminWID.toString())
        adminTopPath.toFile().mkdirs()
        val fileData = "0".repeat(1024).encodeToByteArray()
        val fileHash = hash(fileData).getOrThrow()
        val devid = RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!

        CommandTest(
            "upload.1",
            SessionState(
                ClientRequest(
                    "UPLOAD", mutableMapOf(
                        "Size" to "1024",
                        "Hash" to fileHash.toString(),
                        "Path" to "/ wsp $adminWID",
                    )
                ), adminWID, LoginState.LoggedIn, devid
            ), ::commandUpload
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            var response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(100)
            response.assertField("TempName") { MServerPath.checkFileName(it) }

            val ostream = socket.getOutputStream()
            ostream.write(fileData)
            response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
        }.run()

        // Test Case #2: Successful resume

        // Wow. Creating a temporary file which simulates interruption is a lot of work. :(
        val adminTempPath = Paths.get(
            setupData.testPath, "topdir", "tmp",
            adminWID.toString()
        )
        adminTempPath.toFile().mkdirs()
        val tempName =
            "${Instant.now().epochSecond}.1024.${UUID.randomUUID().toString().lowercase()}"
        val tempFile = Paths.get(adminTempPath.toString(), tempName).toFile()
        tempFile.createNewFile()
        tempFile.writeText("0".repeat(512))

        CommandTest(
            "upload.2",
            SessionState(
                ClientRequest(
                    "UPLOAD", mutableMapOf(
                        "Size" to "1024",
                        "Hash" to fileHash.toString(),
                        "Path" to "/ wsp $adminWID",
                        "TempName" to tempName,
                        "Offset" to "512",
                    )
                ), adminWID, LoginState.LoggedIn, devid
            ), ::commandUpload
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            var response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(100)
            response.assertField("TempName") { MServerPath.checkFileName(it) }

            val ostream = socket.getOutputStream()
            ostream.write("0".repeat(512).encodeToByteArray())
            response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)

            response.assertField("FileName") { it == tempName }
            val uploadedFile = Paths.get(adminTopPath.toString(), tempName).toFile()
            assert(uploadedFile.exists())
            assertEquals(1024, uploadedFile.length())
            assert(hashFile(uploadedFile.path.toString()).getOrThrow() == fileHash)
        }.run()
    }

    @Test
    fun uploadReplaceTest() {
        val setupData = setupTest("handlers.uploadReplace")
        ServerConfig.load().getOrThrow()
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        // Test Case #1: Successful replace
        val adminTopPath = Paths.get(setupData.testPath, "topdir", "wsp", adminWID.toString())
        adminTopPath.toFile().mkdirs()
        val replacedInfo = makeTestFile(adminTopPath.toString(), fileSize = 10240)
        val fileData = "0".repeat(1024).encodeToByteArray()
        val fileHash = hash(fileData).getOrThrow()
        val devid = RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!

        CommandTest(
            "uploadReplace.1",
            SessionState(
                ClientRequest(
                    "UPLOAD", mutableMapOf(
                        "Size" to "1024",
                        "Hash" to fileHash.toString(),
                        "Path" to "/ wsp $adminWID",
                        "Replaces" to "/ wsp $adminWID ${replacedInfo.first}"
                    )
                ), adminWID, LoginState.LoggedIn, devid
            ), ::commandUpload
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            ServerResponse.receive(socket.getInputStream()).getOrThrow().assertReturnCode(100)

            val ostream = socket.getOutputStream()
            ostream.write(fileData)
            val response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
            val replacedPath = Paths.get(adminTopPath.toString(), replacedInfo.first)
            assert(!replacedPath.exists())
            val newPath = Paths.get(adminTopPath.toString(), response.data["FileName"]!!)
            assert(newPath.exists())

        }.run()
    }

    @Test
    fun uploadErrorsTest() {
        val setupData = setupTest("handlers.uploadErrors")
        ServerConfig.load().getOrThrow()
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        val adminTopPath = Paths.get(setupData.testPath, "topdir", "wsp", adminWID.toString())
        adminTopPath.toFile().mkdirs()
        makeTestFile(adminTopPath.toString(), "upload.txt", 4096)
        val tempPath = Paths.get(adminTopPath.toString(), "upload.txt").toString()
        val fileHash = hashFile(tempPath).getOrThrow()
        val devid = RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!
        setQuota(DBConn(), adminWID, 8192)

        // Test Case #1: Quota limit
        CommandTest(
            "uploadErrors.1",
            SessionState(
                ClientRequest(
                    "UPLOAD", mutableMapOf(
                        "Size" to "10240",
                        "Hash" to fileHash.toString(),
                        "Path" to "/ wsp $adminWID",
                    )
                ), adminWID, LoginState.LoggedIn, devid
            ), ::commandUpload
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            ServerResponse.receive(socket.getInputStream()).getOrThrow().assertReturnCode(409)
        }.run()

        // Test Case #2: Hash mismatch
        CommandTest(
            "uploadErrors.2",
            SessionState(
                ClientRequest(
                    "UPLOAD", mutableMapOf(
                        "Size" to "1024",
                        "Hash" to "BLAKE2B-256:asdcvbed",
                        "Path" to "/ wsp $adminWID",
                    )
                ), adminWID, LoginState.LoggedIn, devid
            ), ::commandUpload
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            ServerResponse.receive(socket.getInputStream()).getOrThrow().assertReturnCode(100)

            val ostream = socket.getOutputStream()
            ostream.write("0".repeat(1024).encodeToByteArray())
            ServerResponse.receive(socket.getInputStream()).getOrThrow().assertReturnCode(410)
        }.run()

        // Test Case #3: Destination doesn't exist
        CommandTest(
            "uploadErrors.3",
            SessionState(
                ClientRequest(
                    "UPLOAD", mutableMapOf(
                        "Size" to "1024",
                        "Hash" to fileHash.toString(),
                        "Path" to "/ wsp $adminWID 12db8776-cc91-4ed9-8dbc-efcc3bf904ac",
                    )
                ), adminWID, LoginState.LoggedIn, devid
            ), ::commandUpload
        ) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            ServerResponse.receive(socket.getInputStream()).getOrThrow().assertReturnCode(404)
        }.run()

    }
}

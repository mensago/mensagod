package mensagod.handlers

import keznacl.hash
import keznacl.hashFile
import libkeycard.RandomID
import libmensago.ClientRequest
import libmensago.MServerPath
import libmensago.ServerResponse
import mensagod.DBConn
import mensagod.LoginState
import mensagod.ServerConfig
import mensagod.SessionState
import mensagod.dbcmds.setQuota
import org.junit.jupiter.api.Assertions.assertEquals
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
        val setupData = setupTest("handlers.downloadTest")
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
        // TODO: Implement test for commandExists()
    }

    @Test
    fun mkDirTest() {
        setupTest("handlers.mkDirTest")
        ServerConfig.load().getOrThrow()
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

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
    fun uploadTest() {
        val setupData = setupTest("handlers.uploadTest")
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
        val setupData = setupTest("handlers.uploadReplaceTest")
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
        val setupData = setupTest("handlers.uploadErrorsTest")
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

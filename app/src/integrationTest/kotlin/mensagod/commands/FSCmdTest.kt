package mensagod.commands

import keznacl.hash
import keznacl.hashFile
import libkeycard.RandomID
import mensagod.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.Socket
import java.nio.file.Paths
import java.time.Instant
import java.util.*

class FSCmdTest {

    @Test
    fun uploadTest() {
        val setupData = setupTest("commands.uploadTest")
        ServerConfig.load().getOrThrow()
        val adminWID = RandomID.fromString(ADMIN_PROFILE_DATA["wid"])!!

        // Test Case #1: Successful file upload
        val adminTopPath = Paths.get(setupData.testPath, "topdir", "wsp", adminWID.toString())
        adminTopPath.toFile().mkdirs()
        val fileData = "0".repeat(1024).encodeToByteArray()
        val fileHash = hash(fileData).getOrThrow()
        val devid = RandomID.fromString(ADMIN_PROFILE_DATA["devid"])!!

        CommandTest("upload.1",
            SessionState(ClientRequest("UPLOAD", mutableMapOf(
                "Size" to "1024",
                "Hash" to fileHash.toString(),
                "Path" to "/ wsp $adminWID",
            )), adminWID, LoginState.LoggedIn, devid), ::commandUpload) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            var response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(100)
            response.assertField("TempName") { MServerPath.validateFileName(it) }

            val ostream = socket.getOutputStream()
            ostream.write(fileData)
            response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(200)
        }.run()

        // Test Case #2: Successful resume

        // Wow. Creating a temporary file which simulates interruption is a lot of work. :(
        val adminTempPath = Paths.get(setupData.testPath, "topdir", "tmp",
            adminWID.toString())
        adminTempPath.toFile().mkdirs()
        val tempName = "${Instant.now().epochSecond}.1024.${UUID.randomUUID().toString().lowercase()}"
        val tempFile = Paths.get(adminTempPath.toString(), tempName).toFile()
        tempFile.createNewFile()
        tempFile.writeText("0".repeat(512))

        CommandTest("upload.2",
            SessionState(ClientRequest("UPLOAD", mutableMapOf(
                "Size" to "1024",
                "Hash" to fileHash.toString(),
                "Path" to "/ wsp $adminWID",
                "TempName" to tempName,
                "Offset" to "512",
            )), adminWID, LoginState.LoggedIn, devid), ::commandUpload) { port ->
            val socket = Socket(InetAddress.getByName("localhost"), port)
            var response = ServerResponse.receive(socket.getInputStream()).getOrThrow()
            response.assertReturnCode(100)
            response.assertField("TempName") { MServerPath.validateFileName(it) }

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

        // TODO: Finish uploadTest test cases
    }
}

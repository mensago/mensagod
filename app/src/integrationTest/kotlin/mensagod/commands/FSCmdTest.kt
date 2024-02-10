package mensagod.commands

import keznacl.hash
import libkeycard.RandomID
import mensagod.*
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.Socket
import java.nio.file.Paths

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

        // TODO: Finish uploadTest test cases
    }
}
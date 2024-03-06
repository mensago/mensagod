package libmensago

import org.junit.jupiter.api.Test

class MimeTypeTest {

    @Test
    fun basicTest() {
        listOf(
            "application/postscript",
            "application/x-mplayer2",
            "audio/basic",
            "video/x-msvideo",
            "image/bmp",
            "text/plain",
            "model/iges"
        ).forEach {
            if (MimeType.fromString(it) == null)
                throw Exception("MimeTypeTest failed on valid data: $it")
        }

        listOf(
            "foo/bar",
            "teXt/plain",
            "application"
        ).forEach {
            if (MimeType.fromString(it) != null)
                throw Exception("MimeTypeTest failed on invalid data: $it")
        }
    }
}
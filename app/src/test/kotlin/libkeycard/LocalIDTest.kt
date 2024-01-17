package libkeycard

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class LocalIDTest {

    @Test
    fun getValue() {

        // -- Tests for valid user IDs

        // Basic ASCII and other Unicode
        val luids = listOf("cavsfan4life",
            "valid_e-mail.123",
            "Valid.but.needs_case-squashed",
            "GoodID",
            "alsogoooood",
            "11111111-1111-1111-1111-111111111111",
            "a".repeat(64),

            // Chinese
            "强",
            "欣怡",
            "零一二三四五六七八九十百千萬億",
            "〇一二三四五六七八九十百千万亿",

            // Hebrew
            "יְהוֹשֻׁעַ",
            "אבגדהוזחט",

            // Tamil
            "அகரன்",
            "௦௧௨௩௪௫௬௭௮௯",

            // Devanagari
            "अजीत",
            "०१२३४५६७८९",

            // Bengali
            "आहना",
            "০১২৩৪৫৬৭৮৯",

            // Greek
            "Νικόλαος",
            "ōαβγδεϝζηθι",

            // Armenian
            "Ալմաստ",
            "ԱԲԳԴԵԶԷԸԹԺ",

            // Khmer
            "សុភាព",
            "០១២៣៤៥៦៧៨៩",

            // Thai
            "ประเสริฐ",
            "๐๑๒๓๔๕๖๗๘๙",

            // Arabic
            "عادل",
            "٨٧٦٥٤٣٢١",

            // Vietnamese
            "Hương",
            "𠬠𠄩𠀧𦊚𠄼𦒹𦉱𠔭𠃩",

            // Cyrillic
            "Александра",
            "авгдеѕзиѳі",

            // Burmese
            "သီရိ",
            "၀၁၂၃၄၅၆၇၈၉",

            // Hangul
            "하늘",
            "영일이삼사오육칠팔구",
        )
        for (luid in luids)
            assertNotNull(LocalID.fromString(luid))

        // -- Test cases to invalidate non-compliant user IDs

        // Invalid because dots are not allowed to be consecutive
        assertNull(LocalID.fromString("invalid..number1"))

        // Invalid because LocalIDs are limited to 64 codepoints
        assertNull(LocalID.fromString("a".repeat(65)))

        // Symbols are also not allowed
        assertNull(LocalID.fromString("invalid#2"))

        // Nor is internal whitespace
        assertNull(LocalID.fromString("invalid number 3"))

        // -- Special test cases

        assertEquals(
            LocalID.fromString("Valid.but.needs_case-squashed").toString(),
            "valid.but.needs_case-squashed")
    }
}
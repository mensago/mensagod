package mensagod

import java.security.SecureRandom

/**
 * The RegCodeGenerator class implements a variant of the Diceware passphrase generation method. A
 * single value is chosen from a cryptographically-secure random number generator. This value can be
 * in the entire range of the word list. To use D&D terms with an example, a 5-word passphrase
 * chosen from the long EFF list, which has 7776 words, is rolled with 5d7776 instead of 25d6. The
 * advantage to this method is that word list size is not arbitrarily limited.
 */
class RegCodeGenerator {

    private val wordSet = loadWordList()!!

    /**
     * Returns a passphrase consisting of the number of words requested from the list. Word
     * count must be at least 3 and any word counts of less than 3 are increased to 3. The words in
     * the passphrase are separated by a space and are not capitalized.
     */
    fun getPassphrase(wordCount: Int): String {

        val count = if (wordCount >= 3) wordCount else 3
        val words = wordSet.toList()
        val out = mutableListOf<String>()

        val rng = SecureRandom.getInstanceStrong()
        repeat(count) { out.add(words[rng.nextInt(words.size)]) }

        return out.joinToString(" ")
    }

    /** Loads the specified word list or returns null if not found */
    private fun loadWordList(): Set<String>? {

        return object {}.javaClass
            .getResourceAsStream("/eff.txt")
            ?.bufferedReader()
            ?.readLines()
            ?.map { it.trim() }
            ?.toSet()
    }
}

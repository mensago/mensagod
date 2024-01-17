package mensagod.dbcmds

import keznacl.EncryptionPair
import keznacl.SigningPair
import mensagod.DBConn
import mensagod.DatabaseCorruptionException
import mensagod.NotConnectedException
import mensagod.ResourceNotFoundException

/**
 * Returns the orgnization's encryption keypair.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws ResourceNotFoundException if the keypair was not found
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun getEncryptionPair(): EncryptionPair {
    val db = DBConn()
    val rs = db.query("""SELECT pubkey,privkey FROM orgkeys WHERE purpose = 'encrypt' 
        ORDER BY rowid DESC LIMIT 1""")
    if (!rs.next()) throw ResourceNotFoundException("org encryption keypair not found")

    return EncryptionPair.fromStrings(rs.getString("pubkey"),
        rs.getString("privkey"))
        .getOrElse { throw DatabaseCorruptionException("bad org encryption keypair") }
}

/**
 * Returns the orgnization's primary signing keypair.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws ResourceNotFoundException if the keypair was not found
 * @throws java.sql.SQLException for database problems, most likely either with your query or with the connection
 */
fun getPrimarySigningPair(): SigningPair {
    val db = DBConn()
    val rs = db.query("""SELECT pubkey,privkey FROM orgkeys WHERE purpose = 'sign' 
        ORDER BY rowid DESC LIMIT 1""")
    if (!rs.next()) throw ResourceNotFoundException("org encryption keypair not found")

    return SigningPair.fromStrings(rs.getString("pubkey"),
        rs.getString("privkey"))
        .getOrElse { throw DatabaseCorruptionException("bad org primary signing keypair") }
}

package mensagod.dbcmds

import keznacl.EncryptionPair
import keznacl.SigningPair
import keznacl.toFailure
import keznacl.toSuccess
import libmensago.NotConnectedException
import libmensago.ResourceNotFoundException
import mensagod.DBConn
import mensagod.DatabaseCorruptionException

/**
 * Returns the orgnization's encryption keypair.
 *
 * @throws NotConnectedException if not connected to the database
 * @throws ResourceNotFoundException if the keypair was not found
 * @throws java.sql.SQLException for database problems, most likely either with your query or with
 * the connection
 * @throws DatabaseCorruptionException if something bad was received from the database itself
 */
fun getEncryptionPair(db: DBConn): Result<EncryptionPair> {
    val rs = db.query(
        """SELECT pubkey,privkey FROM orgkeys WHERE purpose = 'encrypt' 
        ORDER BY rowid DESC LIMIT 1"""
    ).getOrElse { return it.toFailure() }
    if (!rs.next())
        return ResourceNotFoundException("org encryption keypair not found").toFailure()

    val out = EncryptionPair.fromStrings(
        rs.getString("pubkey"),
        rs.getString("privkey")
    )
        .getOrElse {
            return DatabaseCorruptionException("bad org encryption keypair").toFailure()
        }
    return out.toSuccess()
}

/**
 * Returns the orgnization's primary signing keypair.
 *
 * @throws NotConnectedException Returned if not connected to the database
 * @throws ResourceNotFoundException Returned if the keypair was not found
 * @throws java.sql.SQLException Returned for database problems, most likely either with your query
 * or with the connection
 * @throws DatabaseCorruptionException Returned if something bad was received from the database
 * itself
 */
fun getPrimarySigningPair(db: DBConn): Result<SigningPair> {
    val rs = db.query(
        """SELECT pubkey,privkey FROM orgkeys WHERE purpose = 'sign' 
        ORDER BY rowid DESC LIMIT 1"""
    ).getOrElse { return it.toFailure() }
    if (!rs.next())
        return ResourceNotFoundException("org encryption keypair not found").toFailure()

    val out = SigningPair.fromStrings(
        rs.getString("pubkey"),
        rs.getString("privkey")
    )
        .getOrElse {
            return DatabaseCorruptionException("bad org primary signing keypair").toFailure()
        }
    return out.toSuccess()
}

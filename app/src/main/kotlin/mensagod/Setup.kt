package mensagod

import java.sql.Connection

/**
 * Empties and resets the server's database to start from a clean slate
 *
 * @throws java.sql.SQLException on database errors
 */
fun resetDB(config: ServerConfig): Connection {

    val db = config.connectToDB()
    val stmt = db.createStatement()

    // Drop all tables in the database
    stmt.addBatch(
        """
    DO ${'$'}${'$'} DECLARE
        r RECORD;
    BEGIN
        FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = current_schema()) LOOP
            EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
        END LOOP;
    END ${'$'}${'$'};
    """
    )

    // Create new ones

    // Lookup table for all workspaces. When any workspace is created, its wid is added here.
    // userid is optional. wtype can be 'individual', 'sharing', 'group', or 'alias'
    stmt.addBatch(
        """CREATE TABLE aliases(rowid SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL,
            alias CHAR(292) NOT NULL);"""
    )

    // For logging different types of failures, such as failed usernanme entry or a server's failure
    // to authenticate for delivery. Information stored here is to ensure that all parties which the
    // server interacts with behave themselves.
    stmt.addBatch(
        """CREATE TABLE failure_log(rowid SERIAL PRIMARY KEY, type VARCHAR(16) NOT NULL,
        id VARCHAR(36), source VARCHAR(36) NOT NULL, count INTEGER,
        last_failure CHAR(20) NOT NULL, lockout_until CHAR(20));"""
    )

    // Devices registered to each individual's workspace
    stmt.addBatch(
        """CREATE TABLE iwkspc_devices(rowid SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL,
        devid CHAR(36) NOT NULL, devkey VARCHAR(1000) NOT NULL,
        devinfo VARCHAR(8192) NOT NULL,
        lastlogin VARCHAR(32) NOT NULL, status VARCHAR(16) NOT NULL);"""
    )

    // Information about individual workspaces
    stmt.addBatch(
        """CREATE TABLE iwkspc_folders(rowid SERIAL PRIMARY KEY, wid char(36) NOT NULL,
        serverpath VARCHAR(512) NOT NULL, clientpath VARCHAR(768) NOT NULL);"""
    )

    // Stores all entries in the keycard tree
    stmt.addBatch(
        """CREATE TABLE keycards(rowid SERIAL PRIMARY KEY, owner VARCHAR(292) NOT NULL,
        creationtime CHAR(20) NOT NULL, index INTEGER NOT NULL,
        entry VARCHAR(8192) NOT NULL, fingerprint VARCHAR(96) NOT NULL);"""
    )

    // Locations for key information packages needed for key exchange to new devices
    stmt.addBatch(
        """CREATE TABLE keyinfo(rowid SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL,
        devid CHAR(36) UNIQUE NOT NULL, path VARCHAR(128));"""
    )

    // Keycard information for the organization
    stmt.addBatch(
        """CREATE TABLE orgkeys(rowid SERIAL PRIMARY KEY, creationtime CHAR(20) NOT NULL, 
        pubkey VARCHAR(7000), privkey VARCHAR(7000) NOT NULL, 
        purpose VARCHAR(8) NOT NULL, fingerprint VARCHAR(96) NOT NULL);"""
    )

    // passcodes table is used for password resets
    stmt.addBatch(
        """CREATE TABLE passcodes(rowid SERIAL PRIMARY KEY, wid VARCHAR(36) NOT NULL UNIQUE,
        passcode VARCHAR(128) NOT NULL, expires CHAR(20) NOT NULL);"""
    )

    // Preregistration information. Entries are removed upon successful account registration.
    stmt.addBatch(
        """CREATE TABLE prereg(rowid SERIAL PRIMARY KEY, wid VARCHAR(36) NOT NULL UNIQUE,
        uid VARCHAR(128), domain VARCHAR(255) NOT NULL, regcode VARCHAR(128));"""
    )

    // Disk quota tracking
    stmt.addBatch(
        """CREATE TABLE quotas(rowid SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL,
        usage BIGINT, quota BIGINT);"""
    )

    /*
        For logging updates made to a workspace. This table is critical to device synchronization.
        The update_data field is specific to the update type.

        Update Types
        1: CREATE. An item has been created. update_data contains the path of the item created. Note
           that this applies both to files and directories
        2: DELETE. An item has een deleted. update_data contains the path of the item created. Note
           that this applies both to files and directories. If a directory has been deleted, all of
           its contents have also been deleted, which improves performance when large directories
           go away.
        3: MOVE. An item has been moved. update_data contains two paths, the source and the
           destination. The source path contains the directory path, and in the case of a file, the
           file name. The destination contains only a folder path.
        4: ROTATE. Keys have been rotated. update_data contains the path to the encrypted key
           storage package.
    */
    stmt.addBatch(
        """CREATE TABLE updates(rowid SERIAL PRIMARY KEY, rid CHAR(36) NOT NULL, wid CHAR(36) NOT NULL,
        update_type INTEGER, update_data VARCHAR(2048), unixtime BIGINT, devid CHAR(36) NOT NULL);"""
    )

    stmt.addBatch(
        """CREATE TABLE workspaces(rowid BIGSERIAL PRIMARY KEY, wid CHAR(36) NOT NULL,
            uid VARCHAR(64), domain VARCHAR(255) NOT NULL, wtype VARCHAR(32) NOT NULL,
            status VARCHAR(16) NOT NULL, password VARCHAR(128), passtype VARCHAR(32),
            salt VARCHAR(32), passparams VARCHAR(128));"""
    )

    stmt.executeBatch()

    return db
}

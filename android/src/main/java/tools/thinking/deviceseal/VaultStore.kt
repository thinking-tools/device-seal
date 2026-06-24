package tools.thinking.deviceseal

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * One persisted record — the Android counterpart of `StoredEntry` in `_types.ts`. The first fields are public
 * metadata; `applicationContext` is non-secret but internal (never returned to callers); everything from
 * `credentialIdentifier` down is an opaque salt, nonce, and ciphertext — inert without a live, user-verified
 * hardware ceremony.
 *
 * `credentialIdentifier` plays the exact role the WebAuthn credential `rawId` plays in the browser: it
 * identifies *which* hardware credential unlocks this entry. Here it is random bytes whose base64url form is
 * the Android Keystore alias of this entry's HMAC key (see [HardwareKey]).
 *
 * Two Android-specific fields have no browser analog:
 *   - [keyBacking] records which secure hardware actually protects the key (StrongBox vs TEE), so the
 *     achieved protection level is visible rather than merely requested.
 *   - [deviceCredentialAllowed] records the verification mode the key was created with, because the access
 *     ceremony must replay the SAME mode (a CryptoObject-bound key and a device-credential key are unlocked
 *     differently). See [HardwareKey]'s two-mode note.
 */
internal data class StoredEntry(
    val identifier: String,
    val username: String,
    val label: String,
    val createdAt: String,
    val applicationContext: String,
    val credentialIdentifier: ByteArray,
    val salt: ByteArray,
    val initializationVector: ByteArray,
    val ciphertext: ByteArray,
    val passphrased: Boolean,
    val keyBacking: KeyBacking,
    val deviceCredentialAllowed: Boolean,
)

/**
 * Local persistence — the Android counterpart of `_storage.ts`. The browser uses IndexedDB; the closest
 * built-in, zero-extra-dependency equivalent on Android is SQLite (`android.database.sqlite`), so the entire
 * store is one tiny table reached through a [SQLiteOpenHelper]. This is deliberately not an EncryptedFile /
 * Jetpack-Security store: just like IndexedDB, the store has no access control beyond the app sandbox and is
 * not meant to be "unstealable". The design instead makes a stolen copy useless — every row holds only public
 * values (salt, credentialIdentifier) and AES-256-GCM ciphertext that is inert without this device's
 * hardware-bound, user-verified HMAC key. No key material is ever written here.
 *
 * Residual exposure, by design: metadata (username, label, createdAt) is stored in cleartext, so a stolen
 * copy reveals which accounts exist — a privacy leak, not a secret one. Tampering can at most deny service:
 * ciphertext cannot be forged, and since the derived key binds whether a passphrase was mixed in, flipping
 * `passphrased` yields the wrong key, never a bypass.
 *
 * All methods here are blocking SQLite calls; [DeviceSeal] invokes them on [kotlinx.coroutines.Dispatchers.IO].
 */
internal class VaultStore(context: Context, databaseName: String) :
    SQLiteOpenHelper(context.applicationContext, databaseName, /* factory = */ null, DATABASE_VERSION) {

    override fun onCreate(db: SQLiteDatabase) {
        // keyPath 'identifier' only — no secondary indexes. listCredentials reads every row and filters in
        // memory (the vault is small), mirroring the browser store which dropped its unused indexes.
        db.execSQL(
            """
            CREATE TABLE $TABLE (
                identifier TEXT PRIMARY KEY NOT NULL,
                username TEXT NOT NULL,
                label TEXT NOT NULL,
                createdAt TEXT NOT NULL,
                applicationContext TEXT NOT NULL,
                credentialIdentifier BLOB NOT NULL,
                salt BLOB NOT NULL,
                initializationVector BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                passphrased INTEGER NOT NULL,
                keyBacking TEXT NOT NULL,
                deviceCredential INTEGER NOT NULL
            )
            """.trimIndent(),
        )
    }

    // First version of the schema; any future change adds its migration here. Kept minimal in this draft.
    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit

    fun save(entry: StoredEntry) {
        val values = ContentValues().apply {
            put("identifier", entry.identifier)
            put("username", entry.username)
            put("label", entry.label)
            put("createdAt", entry.createdAt)
            put("applicationContext", entry.applicationContext)
            put("credentialIdentifier", entry.credentialIdentifier)
            put("salt", entry.salt)
            put("initializationVector", entry.initializationVector)
            put("ciphertext", entry.ciphertext)
            put("passphrased", if (entry.passphrased) 1 else 0)
            put("keyBacking", entry.keyBacking.name)
            put("deviceCredential", if (entry.deviceCredentialAllowed) 1 else 0)
        }
        // Insert-or-replace keyed on the identifier primary key (the analog of IndexedDB `put`).
        writableDatabase.insertWithOnConflict(TABLE, null, values, SQLiteDatabase.CONFLICT_REPLACE)
    }

    fun load(identifier: String): StoredEntry? =
        readableDatabase.query(TABLE, null, "identifier = ?", arrayOf(identifier), null, null, null)
            .use { cursor -> if (cursor.moveToFirst()) cursor.toEntry() else null }

    fun loadAll(): List<StoredEntry> =
        readableDatabase.query(TABLE, null, null, null, null, null, "createdAt ASC")
            .use { cursor ->
                buildList {
                    while (cursor.moveToNext()) add(cursor.toEntry())
                }
            }

    /** Deletes one record by identifier. Returns true if a row was removed (SQLite reports the row count). */
    fun delete(identifier: String): Boolean =
        writableDatabase.delete(TABLE, "identifier = ?", arrayOf(identifier)) > 0

    /** Empties the table in one statement and returns how many rows were removed. */
    fun clear(): Int = writableDatabase.delete(TABLE, null, null)

    private fun android.database.Cursor.toEntry(): StoredEntry = StoredEntry(
        identifier = getString(getColumnIndexOrThrow("identifier")),
        username = getString(getColumnIndexOrThrow("username")),
        label = getString(getColumnIndexOrThrow("label")),
        createdAt = getString(getColumnIndexOrThrow("createdAt")),
        applicationContext = getString(getColumnIndexOrThrow("applicationContext")),
        credentialIdentifier = getBlob(getColumnIndexOrThrow("credentialIdentifier")),
        salt = getBlob(getColumnIndexOrThrow("salt")),
        initializationVector = getBlob(getColumnIndexOrThrow("initializationVector")),
        ciphertext = getBlob(getColumnIndexOrThrow("ciphertext")),
        passphrased = getInt(getColumnIndexOrThrow("passphrased")) != 0,
        keyBacking = runCatching { KeyBacking.valueOf(getString(getColumnIndexOrThrow("keyBacking"))) }
            .getOrDefault(KeyBacking.TEE),
        deviceCredentialAllowed = getInt(getColumnIndexOrThrow("deviceCredential")) != 0,
    )

    private companion object {
        const val TABLE = "entries"
        const val DATABASE_VERSION = 1
    }
}

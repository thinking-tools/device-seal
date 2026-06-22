# Breaking Changes

This is a comprehensive list of the breaking changes introduced in the major version releases of `device-seal` library.

## Versions

- [Version v1.0.1](#version-101)

## Version 1.0.1

**The key-derivation envelope changed. Secrets stored by any `0.0.x` build can no longer be decrypted.**

The public TypeScript API (exports, option and return shapes) is unchanged — this is a stored-data format break, not a source break. Two changes alter the derived key:

- The WebAuthn PRF is now evaluated over `SHA-512(salt)` instead of the raw 32-byte salt. This affects **every** entry.
- When a `passphrase` is set, its PBKDF2-SHA-512 material is now folded into the **PRF eval input** (length-framed with the salt) as well as the HKDF input. Previously it went into the HKDF input only. This affects passphrase-protected entries additionally.

**Migration:** none — by design there is no recovery. Re-create affected credentials with `createCredential` (back up the returned secret first); clear the orphaned entries with `removeCredential` / `wipeVault`.

/**
 * The four cryptographic primitives and the key ring &mdash; {@code spec/14-security.md}.
 *
 *  <p>XChaCha20-Poly1305, Argon2id, HKDF-SHA256 and HMAC-SHA256, all hand-written
 *  because none of the first two is in the JDK. Also the keyslots, the nonce
 *  discipline of &sect;4.1, and the superblock MAC.
 */
package org.dizitart.cryptand.crypto;

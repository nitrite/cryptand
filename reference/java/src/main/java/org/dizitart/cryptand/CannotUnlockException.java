package org.dizitart.cryptand;

/**
 * An encrypted file, and no key or the wrong key —
 * {@code spec/00-conventions.md} §9.
 *
 * <p>Reported <strong>identically</strong> for a missing keyslot and a wrong
 * password. Distinguishing them tells an attacker which of the two they got
 * wrong, and the format has no use for the distinction. The file is never
 * opened partially.
 */
public final class CannotUnlockException extends CryptandException {

    public CannotUnlockException(String message) {
        super(message);
    }
}

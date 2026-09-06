package org.dizitart.cryptand;

/**
 * A second process tried to open the database for writing —
 * {@code spec/01-container.md} §10.
 *
 * <p>One writing process per database, enforced by an exclusive advisory lock
 * held for the writing lifetime. The spec forbids the fallback that would be
 * convenient here: a second writer MUST fail with a clear "locked by another
 * process" error and MUST NOT open anyway.
 */
public final class LockedException extends CryptandException {

    public LockedException(String message) {
        super(message);
    }
}

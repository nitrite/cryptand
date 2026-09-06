package org.dizitart.cryptand;

/**
 * A transaction's write set collided with a batch sequenced after it began —
 * {@code spec/10-transactions.md} §3.
 *
 * <p>The transaction aborts. The format deliberately does not define automatic
 * retry: whether a retry is safe depends on what the caller was doing, and an
 * engine that retries silently turns a lost update into a duplicated one.
 */
public final class ConflictException extends CryptandException {

    public ConflictException(String message) {
        super(message);
    }
}

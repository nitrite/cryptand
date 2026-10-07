package org.dizitart.cryptand;

/**
 * Base of the error taxonomy of {@code spec/00-conventions.md} §9.
 *
 * <p>The spec is emphatic that these classes MUST NOT be conflated: "your disk
 * has a bad sector" and "someone edited your database" call for different
 * responses, and an implementation that reports one as the other has removed
 * the caller's ability to tell them apart.
 *
 * <p>These are unchecked. Every one of them is a condition a caller may
 * reasonably let propagate — an unreadable database is not something most call
 * sites can do anything about — and the alternative decorates the whole engine
 * with {@code throws} clauses that nobody reads.
 */
public abstract class CryptandException extends RuntimeException {

    protected CryptandException(String message) {
        super(message);
    }

    protected CryptandException(String message, Throwable cause) {
        super(message, cause);
    }
}

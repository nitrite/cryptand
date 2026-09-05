package org.dizitart.cryptand;

/**
 * A declared length would not fit its container, or exceeds a limit of
 * {@code spec/00-conventions.md} §8.
 *
 * <p>Raised <em>before</em> any allocation. {@code spec/14-security.md} §9.1
 * makes that a security requirement rather than a robustness one: opening a
 * file another party produced is what this format exists for, so every reader
 * is a parser of hostile input and must never allocate an attacker-chosen size.
 */
public final class LimitException extends CryptandException {

    public LimitException(String message) {
        super(message);
    }
}

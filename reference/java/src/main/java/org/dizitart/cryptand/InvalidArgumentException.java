package org.dizitart.cryptand;

/** The caller asked the library to write something the format forbids. */
public final class InvalidArgumentException extends CryptandException {

    public InvalidArgumentException(String message) {
        super(message);
    }
}

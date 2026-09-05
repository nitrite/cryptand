package org.dizitart.cryptand;

/**
 * The file requires something this implementation cannot do.
 *
 * <p>{@code spec/00-conventions.md} §9: an unknown <em>required</em> feature
 * bit means refuse to open, naming the bit. An unknown <em>optional</em> bit
 * means open anyway and leave the structures it governs alone — that case is
 * not an error and never reaches here.
 */
public final class UnsupportedFeatureException extends CryptandException {

    public UnsupportedFeatureException(String message) {
        super(message);
    }
}

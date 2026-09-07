/**
 * CVE, the value encoding &mdash; {@code spec/02-value-encoding.md}.
 *
 *  <p>A tagged byte encoding with a fixed type set and no constructor dispatch, so
 *  that opening a hostile file cannot instantiate a class. That property is the
 *  single largest security improvement in the format and it costs nothing.
 */
package org.dizitart.cryptand.value;

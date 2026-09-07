/**
 * Geometry and ISO WKB &mdash; {@code spec/08-spatial.md}.
 *
 *  <p>EWKB is refused: PostGIS sets the high bits of the same type word ISO uses
 *  additively, so a reader that accepts both decodes coordinates as garbage
 *  without raising an error.
 */
package org.dizitart.cryptand.geom;

/**
 * The file container: pages, the pager, the superblock &mdash; {@code spec/01-container.md}.
 *
 *  <p>This is the layer that turns a file into numbered pages, and the only layer
 *  that touches the disk. Encryption sits inside {@link org.dizitart.cryptand.container.Pager}
 *  rather than above it, which is what makes every page &mdash; B+tree, segment,
 *  catalog &mdash; encrypted by construction.
 */
package org.dizitart.cryptand.container;

/**
 * The public API of the Cryptand reference implementation.
 *
 *  <p>Everything an application touches lives here: open a {@link org.dizitart.cryptand.Database},
 *  get a {@link org.dizitart.cryptand.Collection}, run a {@link org.dizitart.cryptand.Transaction},
 *  hold a {@link org.dizitart.cryptand.Snapshot}. The exception hierarchy is here too, because a
 *  caller catches it.
 *
 *  <p>The sub-packages are the engine, grouped by the specification chapter each
 *  implements, and are internal: they are {@code public} only because the split
 *  across packages requires it, and no compatibility is promised for them.
 *
 *  <ul>
 *    <li>{@code util}      &mdash; {@code spec/00-conventions.md}, the byte primitives
 *    <li>{@code container} &mdash; {@code spec/01-container.md}, pages, the pager, the superblock
 *    <li>{@code value}     &mdash; {@code spec/02-value-encoding.md}, CVE
 *    <li>{@code key}       &mdash; {@code spec/03-key-encoding.md}, CKE
 *    <li>{@code lsm}       &mdash; {@code spec/04-segments.md} and {@code spec/10-transactions.md}
 *    <li>{@code index}     &mdash; {@code spec/06}&ndash;{@code 09}, the index kinds
 *    <li>{@code geom}      &mdash; {@code spec/08-spatial.md}, WKB and the predicates
 *    <li>{@code text}      &mdash; {@code spec/07-fulltext.md}, the {@code cryptand.std.v1} analyzer
 *    <li>{@code crypto}    &mdash; {@code spec/14-security.md}, the four primitives and the key ring
 *    <li>{@code ops}       &mdash; {@code spec/13-operations.md}, backup, verify, repair, metrics
 *    <li>{@code tool}      &mdash; the cross-language gate's driver; not part of the library
 *  </ul>
 */
package org.dizitart.cryptand;

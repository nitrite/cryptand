/**
 * The LSM engine: segments, the manifest, the value log &mdash;
 *  {@code spec/04-segments.md} and {@code spec/10-transactions.md}.
 *
 *  <p>Lazy levelling with unconditional key&ndash;value separation at
 *  {@code vlog_min}, and no write-ahead log: the value-log record and the L0
 *  segment entry <em>are</em> the durability records.
 */
package org.dizitart.cryptand.lsm;

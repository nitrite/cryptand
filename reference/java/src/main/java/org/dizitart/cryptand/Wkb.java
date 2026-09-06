package org.dizitart.cryptand;

import java.util.ArrayList;
import java.util.List;

/**
 * ISO Well-Known Binary — {@code spec/08-spatial.md} §1.
 *
 * <p>Chosen because it is the universal geometry interchange form: JTS reads
 * and writes it natively, which retires the {@code WKTReader} round trip that
 * costs a text parse per geometry on the Java side today.
 *
 * <p><strong>ISO WKB, and only ISO WKB.</strong> PostGIS's EWKB signals Z, M
 * and an embedded SRID by setting high bits of the same type word that ISO uses
 * <em>additively</em>, so the two conventions are not distinguishable by a
 * reader that accepts both: a {@code PointZ} is {@code 1001} in ISO and
 * {@code 0x80000001} in EWKB, and a decoder that guesses wrong reads
 * coordinates as garbage. A type word with any of the three high bits set is
 * rejected here rather than interpreted.
 */
public final class Wkb {

    private Wkb() {
    }

    public static final int POINT = 1;
    public static final int LINE_STRING = 2;
    public static final int POLYGON = 3;
    public static final int MULTI_POINT = 4;
    public static final int MULTI_LINE_STRING = 5;
    public static final int MULTI_POLYGON = 6;
    public static final int GEOMETRY_COLLECTION = 7;

    /** ISO adds these to the base type code; EWKB sets high bits instead. */
    public static final int Z_OFFSET = 1000;
    public static final int M_OFFSET = 2000;
    public static final int ZM_OFFSET = 3000;

    private static final int EWKB_Z = 0x80000000;
    private static final int EWKB_M = 0x40000000;
    private static final int EWKB_SRID = 0x20000000;

    /** An axis-aligned bounding box in X, Y, Z, M order — the fixed order of §3. */
    public record Box(double[] min, double[] max) {

        public int dimensions() {
            return min.length;
        }

        /** {@code min = +Inf, max = -Inf}: a geometry with no coordinates. */
        public static Box empty(int dimensions) {
            double[] min = new double[dimensions];
            double[] max = new double[dimensions];
            java.util.Arrays.fill(min, Double.POSITIVE_INFINITY);
            java.util.Arrays.fill(max, Double.NEGATIVE_INFINITY);
            return new Box(min, max);
        }

        public boolean isEmpty() {
            for (int i = 0; i < min.length; i++) {
                if (min[i] > max[i]) {
                    return true;
                }
            }
            return false;
        }

        public boolean intersects(Box other) {
            if (isEmpty() || other.isEmpty()) {
                return false;
            }
            int n = Math.min(min.length, other.min.length);
            for (int i = 0; i < n; i++) {
                if (min[i] > other.max[i] || other.min[i] > max[i]) {
                    return false;
                }
            }
            return true;
        }

        public boolean contains(Box other) {
            if (isEmpty() || other.isEmpty()) {
                return false;
            }
            int n = Math.min(min.length, other.min.length);
            for (int i = 0; i < n; i++) {
                if (other.min[i] < min[i] || other.max[i] > max[i]) {
                    return false;
                }
            }
            return true;
        }

        public Box union(Box other) {
            if (isEmpty()) {
                return other;
            }
            if (other.isEmpty()) {
                return this;
            }
            int n = min.length;
            double[] lo = new double[n];
            double[] hi = new double[n];
            for (int i = 0; i < n; i++) {
                lo[i] = Math.min(min[i], other.min[i]);
                hi[i] = Math.max(max[i], other.max[i]);
            }
            return new Box(lo, hi);
        }

        public double area() {
            if (isEmpty()) {
                return 0;
            }
            double a = 1;
            for (int i = 0; i < min.length; i++) {
                a *= max[i] - min[i];
            }
            return a;
        }

        /** Squared planar distance from a point to this box; 0 when inside. */
        public double squaredDistanceTo(double[] point) {
            double sum = 0;
            for (int i = 0; i < Math.min(min.length, point.length); i++) {
                double d = point[i] < min[i] ? min[i] - point[i]
                        : point[i] > max[i] ? point[i] - max[i] : 0;
                sum += d * d;
            }
            return sum;
        }

        public Box expandedBy(double radius) {
            int n = min.length;
            double[] lo = new double[n];
            double[] hi = new double[n];
            for (int i = 0; i < n; i++) {
                lo[i] = min[i] - radius;
                hi[i] = max[i] + radius;
            }
            return new Box(lo, hi);
        }

        @Override
        public String toString() {
            return java.util.Arrays.toString(min) + ".." + java.util.Arrays.toString(max);
        }
    }

    /** Every coordinate in a geometry, flattened, with the axis count it carries. */
    public record Coordinates(List<double[]> points, int axes) {
    }

    /**
     * The envelope of a WKB geometry, in as many dimensions as it carries.
     *
     * <p>{@code dimensions} clamps the result: an R-tree indexes the XY
     * envelope only unless the index declares more.
     */
    public static Box envelope(byte[] wkb, int dimensions) {
        Coordinates c = coordinates(wkb);
        if (c.points().isEmpty()) {
            return Box.empty(dimensions);
        }
        if (dimensions > c.axes()) {
            throw new InvalidArgumentException("a " + dimensions
                    + "-dimensional index needs a geometry with at least " + dimensions
                    + " axes; this one has " + c.axes()
                    + " (spec/08-spatial.md §3 rejects it rather than indexing M in Z's slot)");
        }
        double[] min = new double[dimensions];
        double[] max = new double[dimensions];
        java.util.Arrays.fill(min, Double.POSITIVE_INFINITY);
        java.util.Arrays.fill(max, Double.NEGATIVE_INFINITY);
        for (double[] p : c.points()) {
            for (int i = 0; i < dimensions; i++) {
                min[i] = Math.min(min[i], p[i]);
                max[i] = Math.max(max[i], p[i]);
            }
        }
        return new Box(min, max);
    }

    /** Parses a geometry into its coordinates, validating the framing as it goes. */
    public static Coordinates coordinates(byte[] wkb) {
        Reader r = new Reader(wkb, 0);
        List<double[]> points = new ArrayList<>();
        int axes = readGeometry(r, points);
        return new Coordinates(points, axes);
    }

    private static int readGeometry(Reader r, List<double[]> out) {
        boolean little = r.byteOrder();
        int type = r.u32(little);
        if ((type & (EWKB_Z | EWKB_M | EWKB_SRID)) != 0) {
            throw new InvalidArgumentException(String.format(
                    "EWKB type word %08x: PostGIS's high-bit convention is not distinguishable "
                            + "from ISO's additive one, so it MUST be rejected rather than guessed at "
                            + "(spec/08-spatial.md §1)", type));
        }
        int base = type % 1000;
        int variant = type / 1000;
        if (variant > 3) {
            throw new InvalidArgumentException("WKB type " + type + " is not an ISO geometry type");
        }
        int axes = switch (variant) {
            case 0 -> 2;
            case 1, 2 -> 3;
            default -> 4;
        };
        switch (base) {
            case POINT -> out.add(r.point(little, axes));
            case LINE_STRING -> readPoints(r, little, axes, out);
            case POLYGON -> {
                int rings = r.u32(little);
                for (int i = 0; i < rings; i++) {
                    readPoints(r, little, axes, out);
                }
            }
            case MULTI_POINT, MULTI_LINE_STRING, MULTI_POLYGON, GEOMETRY_COLLECTION -> {
                int n = r.u32(little);
                for (int i = 0; i < n; i++) {
                    int childAxes = readGeometry(r, out);
                    if (base != GEOMETRY_COLLECTION && childAxes != axes) {
                        throw new InvalidArgumentException(
                                "a multi-geometry's parts disagree on dimensionality");
                    }
                }
            }
            default -> throw new InvalidArgumentException("WKB geometry type " + base + " is not one of "
                    + "Point, LineString, Polygon, MultiPoint, MultiLineString, MultiPolygon "
                    + "or GeometryCollection");
        }
        return axes;
    }

    private static void readPoints(Reader r, boolean little, int axes, List<double[]> out) {
        int n = r.u32(little);
        if (n < 0 || (long) n * axes * 8 > r.remaining()) {
            throw new LimitException("WKB declares " + Integer.toUnsignedString(n)
                    + " points, which do not fit the remaining " + r.remaining() + " bytes");
        }
        for (int i = 0; i < n; i++) {
            out.add(r.point(little, axes));
        }
    }

    // --- writers, for tests and for tooling -----------------------------

    public static byte[] point(double x, double y) {
        return new ByteWriter(21).u8(1).u32(POINT).f64(x).f64(y).toBytes();
    }

    public static byte[] pointZ(double x, double y, double z) {
        return new ByteWriter(29).u8(1).u32(POINT + Z_OFFSET).f64(x).f64(y).f64(z).toBytes();
    }

    public static byte[] lineString(double[]... points) {
        ByteWriter w = new ByteWriter(9 + points.length * 16);
        w.u8(1).u32(LINE_STRING).u32(points.length);
        for (double[] p : points) {
            w.f64(p[0]).f64(p[1]);
        }
        return w.toBytes();
    }

    /** A closed rectangle, as a one-ring polygon. */
    public static byte[] rectangle(double minX, double minY, double maxX, double maxY) {
        ByteWriter w = new ByteWriter(93);
        w.u8(1).u32(POLYGON).u32(1).u32(5);
        double[][] ring = {{minX, minY}, {maxX, minY}, {maxX, maxY}, {minX, maxY}, {minX, minY}};
        for (double[] p : ring) {
            w.f64(p[0]).f64(p[1]);
        }
        return w.toBytes();
    }

    private static final class Reader {
        private final byte[] b;
        private int pos;

        Reader(byte[] b, int pos) {
            this.b = b;
            this.pos = pos;
        }

        int remaining() {
            return b.length - pos;
        }

        boolean byteOrder() {
            require(1);
            int marker = b[pos++] & 0xFF;
            if (marker != 0 && marker != 1) {
                throw new InvalidArgumentException(
                        "WKB byte-order marker is " + marker + ", must be 0 or 1");
            }
            return marker == 1;
        }

        int u32(boolean little) {
            require(4);
            int v = 0;
            if (little) {
                for (int i = 3; i >= 0; i--) {
                    v = (v << 8) | (b[pos + i] & 0xFF);
                }
            } else {
                for (int i = 0; i < 4; i++) {
                    v = (v << 8) | (b[pos + i] & 0xFF);
                }
            }
            pos += 4;
            return v;
        }

        double[] point(boolean little, int axes) {
            double[] p = new double[axes];
            for (int i = 0; i < axes; i++) {
                p[i] = f64(little);
            }
            return p;
        }

        double f64(boolean little) {
            require(8);
            long v = 0;
            if (little) {
                for (int i = 7; i >= 0; i--) {
                    v = (v << 8) | (b[pos + i] & 0xFFL);
                }
            } else {
                for (int i = 0; i < 8; i++) {
                    v = (v << 8) | (b[pos + i] & 0xFFL);
                }
            }
            pos += 8;
            return Double.longBitsToDouble(v);
        }

        private void require(int n) {
            if (pos + n > b.length) {
                throw new LimitException("WKB ends after " + b.length
                        + " bytes; " + n + " more were needed at " + pos);
            }
        }
    }
}

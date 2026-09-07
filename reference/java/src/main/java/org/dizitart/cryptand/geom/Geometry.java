package org.dizitart.cryptand.geom;

import org.dizitart.cryptand.InvalidArgumentException;
import org.dizitart.cryptand.LimitException;

import java.util.ArrayList;
import java.util.List;

/**
 * Exact planar predicates over WKB geometries — the second phase of
 * {@code spec/08-spatial.md} §4.
 *
 * <p>The two-phase rule is normative: <strong>the R-tree returns candidates by
 * bounding box, and the exact predicate is evaluated on the geometry.</strong>
 * An implementation MUST NOT return box-level results as if they were exact.
 * This class is that second phase, and it is the difference between Nitrite's
 * spatial queries meaning the same thing in Java and in Rust.
 *
 * <p>Everything here is planar and in the coordinate system of the data.
 * Geodesic distance is an SDK-level query option: it changes which candidate box
 * to expand by, not the format.
 */
public final class Geometry {

    private Geometry() {
    }

    /** A geometry decomposed into the rings and paths the predicates work on. */
    public record Shape(List<double[][]> polygons, List<double[][]> lines, List<double[]> points) {

        boolean isEmpty() {
            return polygons.isEmpty() && lines.isEmpty() && points.isEmpty();
        }
    }

    public static Shape parse(byte[] wkb) {
        List<double[][]> polygons = new ArrayList<>();
        List<double[][]> lines = new ArrayList<>();
        List<double[]> points = new ArrayList<>();
        walk(wkb, polygons, lines, points);
        return new Shape(polygons, lines, points);
    }

    private static void walk(byte[] wkb, List<double[][]> polygons, List<double[][]> lines,
                             List<double[]> points) {
        // Reuse the validating reader: rings and paths come out in order, and a
        // polygon's first ring is its shell with the rest as holes.
        Parts p = Parts.of(wkb);
        polygons.addAll(p.polygons());
        lines.addAll(p.lines());
        points.addAll(p.points());
    }

    // ==================================================================
    // predicates
    // ==================================================================

    public static boolean intersects(byte[] a, byte[] b) {
        Shape x = parse(a);
        Shape y = parse(b);
        if (x.isEmpty() || y.isEmpty()) {
            return false;
        }
        for (double[] p : x.points()) {
            if (covers(y, p)) {
                return true;
            }
        }
        for (double[] p : y.points()) {
            if (covers(x, p)) {
                return true;
            }
        }
        for (double[][] path : allPaths(x)) {
            for (double[][] other : allPaths(y)) {
                if (pathsCross(path, other)) {
                    return true;
                }
            }
        }
        // One wholly inside the other, with no boundary crossing.
        for (double[][] ring : allPaths(x)) {
            if (ring.length > 0 && covers(y, ring[0])) {
                return true;
            }
        }
        for (double[][] ring : allPaths(y)) {
            if (ring.length > 0 && covers(x, ring[0])) {
                return true;
            }
        }
        return false;
    }

    /** Every point of {@code inner} lies in {@code outer}, and no boundary is crossed. */
    public static boolean contains(byte[] outer, byte[] inner) {
        Shape o = parse(outer);
        Shape i = parse(inner);
        if (o.isEmpty() || i.isEmpty()) {
            return false;
        }
        for (double[] p : i.points()) {
            if (!covers(o, p)) {
                return false;
            }
        }
        for (double[][] path : allPaths(i)) {
            for (double[] p : path) {
                if (!covers(o, p)) {
                    return false;
                }
            }
            // A path may leave and re-enter between two vertices that are both
            // inside, so the boundary has to be tested too.
            for (double[][] boundary : allPaths(o)) {
                if (pathsProperlyCross(path, boundary)) {
                    return false;
                }
            }
        }
        return true;
    }

    public static boolean within(byte[] inner, byte[] outer) {
        return contains(outer, inner);
    }

    /** Planar Euclidean distance, 0 when the point lies on or inside the geometry. */
    public static double distance(byte[] geometry, double x, double y) {
        Shape s = parse(geometry);
        double[] p = {x, y};
        if (covers(s, p)) {
            return 0;
        }
        double best = Double.POSITIVE_INFINITY;
        for (double[] q : s.points()) {
            best = Math.min(best, Math.hypot(q[0] - x, q[1] - y));
        }
        for (double[][] path : allPaths(s)) {
            for (int i = 0; i + 1 < path.length; i++) {
                best = Math.min(best, pointToSegment(p, path[i], path[i + 1]));
            }
        }
        return best;
    }

    public static boolean near(byte[] geometry, double x, double y, double radius) {
        return distance(geometry, x, y) <= radius;
    }

    // ==================================================================
    // primitives
    // ==================================================================

    private static List<double[][]> allPaths(Shape s) {
        List<double[][]> out = new ArrayList<>(s.polygons());
        out.addAll(s.lines());
        return out;
    }

    /** Whether a point is inside or on the boundary of any part of the shape. */
    static boolean covers(Shape s, double[] p) {
        for (double[] q : s.points()) {
            if (q[0] == p[0] && q[1] == p[1]) {
                return true;
            }
        }
        for (double[][] line : s.lines()) {
            for (int i = 0; i + 1 < line.length; i++) {
                if (pointToSegment(p, line[i], line[i + 1]) == 0) {
                    return true;
                }
            }
        }
        // Rings alternate shell, holes, shell, holes: a point in an odd number
        // of rings of one polygon is inside it, which is the even-odd rule and
        // is what makes holes work without tracking which ring is which.
        int crossings = 0;
        for (double[][] ring : s.polygons()) {
            for (int i = 0; i + 1 < ring.length; i++) {
                if (pointToSegment(p, ring[i], ring[i + 1]) == 0) {
                    return true;
                }
            }
            if (pointInRing(p, ring)) {
                crossings++;
            }
        }
        return crossings % 2 == 1;
    }

    /** Ray casting, counting crossings of a ray to +X. */
    static boolean pointInRing(double[] p, double[][] ring) {
        boolean inside = false;
        for (int i = 0, j = ring.length - 1; i < ring.length; j = i++) {
            double xi = ring[i][0];
            double yi = ring[i][1];
            double xj = ring[j][0];
            double yj = ring[j][1];
            if ((yi > p[1]) != (yj > p[1])
                    && p[0] < (xj - xi) * (p[1] - yi) / (yj - yi) + xi) {
                inside = !inside;
            }
        }
        return inside;
    }

    static boolean pathsCross(double[][] a, double[][] b) {
        for (int i = 0; i + 1 < a.length; i++) {
            for (int j = 0; j + 1 < b.length; j++) {
                if (segmentsIntersect(a[i], a[i + 1], b[j], b[j + 1])) {
                    return true;
                }
            }
        }
        return false;
    }

    /** As {@link #pathsCross}, but ignoring mere touching at an endpoint. */
    static boolean pathsProperlyCross(double[][] a, double[][] b) {
        for (int i = 0; i + 1 < a.length; i++) {
            for (int j = 0; j + 1 < b.length; j++) {
                if (segmentsIntersect(a[i], a[i + 1], b[j], b[j + 1])
                        && !sharesEndpoint(a[i], a[i + 1], b[j], b[j + 1])) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean sharesEndpoint(double[] p1, double[] p2, double[] q1, double[] q2) {
        return same(p1, q1) || same(p1, q2) || same(p2, q1) || same(p2, q2);
    }

    private static boolean same(double[] a, double[] b) {
        return a[0] == b[0] && a[1] == b[1];
    }

    static boolean segmentsIntersect(double[] p1, double[] p2, double[] q1, double[] q2) {
        double d1 = cross(q1, q2, p1);
        double d2 = cross(q1, q2, p2);
        double d3 = cross(p1, p2, q1);
        double d4 = cross(p1, p2, q2);
        if (((d1 > 0 && d2 < 0) || (d1 < 0 && d2 > 0))
                && ((d3 > 0 && d4 < 0) || (d3 < 0 && d4 > 0))) {
            return true;
        }
        return (d1 == 0 && onSegment(q1, q2, p1))
                || (d2 == 0 && onSegment(q1, q2, p2))
                || (d3 == 0 && onSegment(p1, p2, q1))
                || (d4 == 0 && onSegment(p1, p2, q2));
    }

    private static double cross(double[] a, double[] b, double[] c) {
        return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0]);
    }

    private static boolean onSegment(double[] a, double[] b, double[] p) {
        return Math.min(a[0], b[0]) <= p[0] && p[0] <= Math.max(a[0], b[0])
                && Math.min(a[1], b[1]) <= p[1] && p[1] <= Math.max(a[1], b[1]);
    }

    static double pointToSegment(double[] p, double[] a, double[] b) {
        double dx = b[0] - a[0];
        double dy = b[1] - a[1];
        if (dx == 0 && dy == 0) {
            return Math.hypot(p[0] - a[0], p[1] - a[1]);
        }
        double t = ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / (dx * dx + dy * dy);
        t = Math.max(0, Math.min(1, t));
        return Math.hypot(p[0] - (a[0] + t * dx), p[1] - (a[1] + t * dy));
    }

    /** A WKB geometry split into polygon rings, line paths and bare points. */
    record Parts(List<double[][]> polygons, List<double[][]> lines, List<double[]> points) {

        static Parts of(byte[] wkb) {
            List<double[][]> polygons = new ArrayList<>();
            List<double[][]> lines = new ArrayList<>();
            List<double[]> points = new ArrayList<>();
            read(new WkbCursor(wkb), polygons, lines, points);
            return new Parts(polygons, lines, points);
        }

        private static void read(WkbCursor c, List<double[][]> polygons, List<double[][]> lines,
                                 List<double[]> points) {
            boolean little = c.byteOrder();
            int type = c.u32(little);
            if ((type & 0xE0000000) != 0) {
                throw new InvalidArgumentException("EWKB is rejected (spec/08-spatial.md §1)");
            }
            int base = type % 1000;
            int axes = switch (type / 1000) {
                case 0 -> 2;
                case 1, 2 -> 3;
                case 3 -> 4;
                default -> throw new InvalidArgumentException("WKB type " + type + " is not ISO");
            };
            switch (base) {
                case Wkb.POINT -> points.add(c.point(little, axes));
                case Wkb.LINE_STRING -> lines.add(c.path(little, axes));
                case Wkb.POLYGON -> {
                    int rings = c.u32(little);
                    for (int i = 0; i < rings; i++) {
                        polygons.add(c.path(little, axes));
                    }
                }
                case Wkb.MULTI_POINT, Wkb.MULTI_LINE_STRING, Wkb.MULTI_POLYGON,
                     Wkb.GEOMETRY_COLLECTION -> {
                    int n = c.u32(little);
                    for (int i = 0; i < n; i++) {
                        read(c, polygons, lines, points);
                    }
                }
                default -> throw new InvalidArgumentException("WKB geometry type " + base
                        + " is not one of the seven §1 supports");
            }
        }
    }

    /** A minimal cursor; {@link Wkb} owns validation, this owns structure. */
    static final class WkbCursor {
        private final byte[] b;
        private int pos;

        WkbCursor(byte[] b) {
            this.b = b;
        }

        boolean byteOrder() {
            require(1);
            int marker = b[pos++] & 0xFF;
            if (marker != 0 && marker != 1) {
                throw new InvalidArgumentException("WKB byte-order marker is " + marker);
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
            double[] p = new double[Math.max(2, axes)];
            for (int i = 0; i < axes; i++) {
                p[i] = f64(little);
            }
            return p;
        }

        double[][] path(boolean little, int axes) {
            int n = u32(little);
            if (n < 0 || (long) n * axes * 8 > b.length - pos) {
                throw new LimitException("WKB path of " + Integer.toUnsignedString(n)
                        + " points does not fit");
            }
            double[][] out = new double[n][];
            for (int i = 0; i < n; i++) {
                out[i] = point(little, axes);
            }
            return out;
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
                throw new LimitException("WKB ends after " + b.length + " bytes");
            }
        }
    }
}

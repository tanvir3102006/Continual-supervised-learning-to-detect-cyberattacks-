package ids;
import java.util.*;
final class Json {
    record F(String sev, String title, String detail, int pts) {
        String json() { return "{\"sev\":" + s(sev) + ",\"title\":" + s(title) + ",\"detail\":" + s(detail) + ",\"pts\":" + pts + "}"; }
    }
    static String s(String v) {
        if (v == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (char c : v.toCharArray()) switch (c) {
            case '"' -> b.append("\\\""); case '\\' -> b.append("\\\\"); case '\n', '\r', '\t' -> b.append(' ');
            default -> b.append(c < 32 ? ' ' : c);
        }
        return b.append('"').toString();
    }
    static String strs(Collection<String> c) { StringJoiner j = new StringJoiner(",", "[", "]"); for (String x : c) j.add(s(x)); return j.toString(); }
    static String findings(List<F> l) { List<F> c = new ArrayList<>(l); c.sort((a, b) -> b.pts() - a.pts()); StringJoiner j = new StringJoiner(",", "[", "]"); for (F f : c) j.add(f.json()); return j.toString(); }
    static int score(List<F> l) { int t = 0; for (F f : l) t += f.pts(); return Math.min(100, t); }
    static String verdict(int sc) { return sc >= 60 ? "Likely malicious" : sc >= 25 ? "Suspicious" : "No threats found"; }
    static void add(List<F> l, String sev, String title, String detail, int pts) { l.add(new F(sev, title, detail, pts)); }
}

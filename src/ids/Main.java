package ids;
import com.sun.net.httpserver.*;
import java.io.*; import java.net.*; import java.nio.file.*; import java.util.*;

/** Zero-dependency full-stack server: REST API + static dashboard. Run: java -cp out ids.Main [port] */
public class Main {
    static DataGen gen; static Classifier cont, naive; static int step, total, batch, lastActive; static long seed; static String cfg = "{}";
    static final StringBuilder hist = new StringBuilder(); static String lastRecall = "[],[]", lastCm = "[]", lastFeed = "[]";
    record Ev(double acc, double tpr, double fpr, double[] recall, int[][] cm) {}

    static double num(Map<String, String> p, String k, double def, double lo, double hi) {
        try { return Math.max(lo, Math.min(hi, Double.parseDouble(p.getOrDefault(k, "" + def)))); } catch (Exception e) { return def; }
    }
    static synchronized void start(Map<String, String> p) {
        LinkedHashSet<Integer> set = new LinkedHashSet<>();
        for (String s : p.getOrDefault("classes", "1,2,3,4").split(",")) try { int c = Integer.parseInt(s.trim()); if (c >= 1 && c < DataGen.CLASSES.length) set.add(c); } catch (Exception ignored) {}
        if (set.isEmpty()) set.add(1);
        int[] att = set.stream().mapToInt(Integer::intValue).toArray();
        batch = (int) num(p, "batch", 200, 50, 1000); double noise = num(p, "noise", 1.2, .5, 2.5), drift = num(p, "drift", .04, 0, .2), lr = num(p, "lr", .03, .005, .2);
        int phase = (int) num(p, "phase", 8, 3, 20), cap = (int) num(p, "cap", 300, 20, 1000);
        seed = System.nanoTime() & 0xffffffffL; // new seed every session -> different results every run
        gen = new DataGen(seed, att, phase, noise, drift); cont = new Classifier(true, lr, cap); naive = new Classifier(false, lr, 0);
        step = 0; total = phase * (att.length + 2); lastActive = 2; hist.setLength(0); lastRecall = "[],[]"; lastCm = "[]"; lastFeed = "[]";
        cfg = String.format(Locale.ROOT, "{\"batch\":%d,\"noise\":%.2f,\"drift\":%.3f,\"lr\":%.3f,\"phase\":%d,\"cap\":%d}", batch, noise, drift, lr, phase, cap);
    }
    static String arr(double[] a) { StringJoiner j = new StringJoiner(",", "[", "]"); for (double v : a) j.add(String.format(Locale.ROOT, "%.4f", v)); return j.toString(); }
    static double acc(Classifier m, List<Sample> s) { int ok = 0; for (Sample x : s) if (m.predict(x.x()) == x.y()) ok++; return (double) ok / s.size(); }

    static Ev eval(Classifier m, List<Sample> t) {
        int C = DataGen.CLASSES.length; int[][] cm = new int[C][C]; for (Sample s : t) cm[s.y()][m.predict(s.x())]++;
        int ok = 0, tp = 0, fn = 0, fp = 0, tn = 0, all = t.size(); double[] rec = new double[C];
        for (int a = 0; a < C; a++) {
            int rs = 0; for (int b = 0; b < C; b++) { rs += cm[a][b];
                if (a == 0) { if (b == 0) tn += cm[a][b]; else fp += cm[a][b]; } else { if (b == 0) fn += cm[a][b]; else tp += cm[a][b]; } }
            ok += cm[a][a]; rec[a] = rs > 0 ? (double) cm[a][a] / rs : -1;
        }
        return new Ev((double) ok / all, tp + fn > 0 ? (double) tp / (tp + fn) : 0, fp + tn > 0 ? (double) fp / (fp + tn) : 0, rec, cm);
    }
    static String m(Ev e, double preq) { return String.format(Locale.ROOT, "{\"acc\":%.4f,\"err\":%.4f,\"tpr\":%.4f,\"fpr\":%.4f,\"preq\":%.4f}", e.acc(), 1 - e.acc(), e.tpr(), e.fpr(), preq); }

    static synchronized void stepOnce() {
        if (step >= total) return;
        List<Sample> b = gen.trainBatch(batch, step); // prequential: predict on new flows first, then learn from them
        double pc = step == 0 ? 0 : acc(cont, b), pn = step == 0 ? 0 : acc(naive, b);
        StringJoiner feed = new StringJoiner(",", "[", "]");
        for (int i = 0; i < Math.min(12, b.size()); i++) { Sample s = b.get(i);
            feed.add(String.format(Locale.ROOT, "{\"truth\":%d,\"cont\":%d,\"naive\":%d,\"conn\":%.2f,\"ips\":%.2f,\"ent\":%.2f}", s.y(), cont.predict(s.x()), naive.predict(s.x()), s.x()[3], s.x()[8], s.x()[9])); }
        cont.learn(b); naive.learn(b);
        List<Sample> t = gen.testSet(100, step); Ev ec = eval(cont, t), en = eval(naive, t);
        if (hist.length() > 0) hist.append(',');
        hist.append(String.format(Locale.ROOT, "{\"step\":%d,\"active\":%d,\"drift\":%.2f,\"c\":%s,\"n\":%s}", step, gen.active(step), gen.drift(step), m(ec, pc), m(en, pn)));
        StringJoiner cm = new StringJoiner(",", "[", "]"); for (int[] r : ec.cm()) cm.add(Arrays.toString(r));
        lastCm = cm.toString(); lastRecall = arr(ec.recall()) + "," + arr(en.recall()); lastFeed = feed.toString(); lastActive = gen.active(step); step++;
    }
    static String list(String[] a) { StringJoiner j = new StringJoiner("\",\"", "[\"", "\"]"); for (String s : a) j.add(s); return j.toString(); }
    static synchronized String state() {
        return "{\"seed\":" + seed + ",\"step\":" + step + ",\"total\":" + total + ",\"flows\":" + (long) step * batch + ",\"cfg\":" + cfg + ",\"active\":" + lastActive
            + ",\"dataSource\":" + Json.s(DataGen.isRealData() ? "CIC-IDS2017 (" + String.format(Locale.ROOT, "%,d", DataGen.getRealCount()) + " real flows)" : "Synthetic DataGen Stream")
            + ",\"isRealData\":" + DataGen.isRealData()
            + ",\"order\":" + Arrays.toString(gen.order()) + ",\"classNames\":" + list(DataGen.CLASSES) + ",\"history\":[" + hist + "],\"recall\":[" + lastRecall + "],\"cm\":" + lastCm + ",\"feed\":" + lastFeed + "}";
    }
    static Map<String, String> query(HttpExchange e) throws IOException {
        Map<String, String> m = new HashMap<>(); String q = e.getRequestURI().getRawQuery();
        if (q != null) for (String p : q.split("&")) { String[] kv = p.split("=", 2); if (kv.length == 2) m.put(kv[0], URLDecoder.decode(kv[1], "UTF-8")); }
        return m;
    }
    static void send(HttpExchange e, int code, String type, byte[] body) throws IOException {
        e.getResponseHeaders().set("Content-Type", type); e.sendResponseHeaders(code, body.length);
        try (OutputStream o = e.getResponseBody()) { o.write(body); }
    }
    static void json(HttpExchange e, String s) throws IOException { send(e, 200, "application/json", s.getBytes("UTF-8")); }

    interface Body { String get() throws Exception; }
    static void guard(HttpExchange e, Body b) throws IOException { try { json(e, b.get()); } catch (Exception x) { json(e, "{\"kind\":\"error\",\"error\":" + Json.s(String.valueOf(x.getMessage())) + "}"); } }
    public static void main(String[] a) throws Exception {
        start(new HashMap<>()); int port = a.length > 0 ? Integer.parseInt(a[0]) : 8080;
        HttpServer s = null;
        for (int p = port; s == null && p < port + 10; p++) try { s = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), p), 0); port = p; } catch (BindException ignored) {}
        if (s == null) throw new IllegalStateException("No free port near " + port);
        s.createContext("/api/state", e -> json(e, state()));
        s.createContext("/api/start", e -> { start(query(e)); json(e, state()); });
        s.createContext("/api/step", e -> { int n = (int) num(query(e), "n", 1, 1, 40); for (int i = 0; i < n; i++) stepOnce(); json(e, state()); });
        s.createContext("/api/scan/url", e -> guard(e, () -> "{\"id\":\"" + UrlScan.start(query(e).getOrDefault("target", "").trim()) + "\"}"));
        s.createContext("/api/scan/status", e -> guard(e, () -> { UrlScan.Job j = UrlScan.JOBS.get(query(e).get("id")); return j == null ? "{\"error\":\"Unknown scan\"}" : j.json(); }));
        s.createContext("/api/scan/feedback", e -> guard(e, () -> { Map<String, String> q = query(e); UrlScan.Job j = UrlScan.JOBS.get(q.get("id")); if (j == null || j.feats == null) return "{\"error\":\"Unknown scan\"}";
            UrlScan.MODEL.learn(j.feats, "1".equals(q.get("label")) ? 1 : 0); return "{\"learned\":" + Math.round(UrlScan.MODEL.predict(j.feats) * 100) + ",\"feedbackCount\":" + UrlScan.MODEL.updates() + "}"; }));
        s.createContext("/api/scan/file", e -> guard(e, () -> { byte[] b = e.getRequestBody().readNBytes(26_000_000); if (b.length > 25_000_000) return "{\"kind\":\"error\",\"error\":\"File is larger than 25 MB.\"}";
            return FileScan.scanFile(URLDecoder.decode(Optional.ofNullable(e.getRequestHeaders().getFirst("X-Filename")).orElse("upload.bin"), "UTF-8"), b); }));
        s.createContext("/api/scan/text", e -> guard(e, () -> FileScan.scanText(new String(e.getRequestBody().readNBytes(500_000), "UTF-8"))));
        s.createContext("/api/scan/shot", e -> { UrlScan.Job j = UrlScan.JOBS.get(query(e).get("id")); if (j == null || j.shot == null) send(e, 404, "text/plain", "none".getBytes()); else send(e, 200, "image/png", j.shot); });
        s.createContext("/scanner", e -> { try { send(e, 200, "text/html; charset=utf-8", Files.readAllBytes(Path.of("web/scanner.html"))); } catch (IOException x) { send(e, 404, "text/plain", "web/scanner.html not found".getBytes()); } });
        s.createContext("/", e -> {
            try { send(e, 200, "text/html; charset=utf-8", Files.readAllBytes(Path.of("web/index.html"))); }
            catch (IOException x) { send(e, 404, "text/plain", "web/index.html not found - set the working directory to the project root".getBytes()); }
        });
        s.start(); System.out.println("ShiftShield dashboard: http://localhost:" + port);
    }
}

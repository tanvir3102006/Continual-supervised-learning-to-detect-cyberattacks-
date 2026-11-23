package ids;
import java.io.*; import java.net.*; import java.net.http.*; import java.nio.charset.StandardCharsets; import java.nio.file.*; import java.security.cert.X509Certificate;
import java.time.*; import java.util.*; import java.util.concurrent.*; import java.util.regex.*; import javax.net.ssl.*;

/** Website / IP scanner: safe fetch with redirect tracking, TLS check, static HTML analysis, and an optional headless-browser capture. All stages run in parallel where possible. */
final class UrlScan {
    static final boolean ALLOW_LOCAL = !"false".equalsIgnoreCase(System.getProperty("scan.allowLocal", "true")); // allows private & local addresses by default
    static final String UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", CAP = "Browser capture (screenshot + live requests)";
    static final ExecutorService POOL = Executors.newCachedThreadPool(r -> { Thread t = new Thread(r); t.setDaemon(true); return t; });
    static final Map<String, Job> JOBS = new ConcurrentHashMap<>(); static final RiskModel MODEL = new RiskModel();
    static final Set<String> BAD_TLD = Set.of("zip","top","xyz","click","gq","tk","ml","cf","ga","work","country","kim","loan","support","rest","cam","icu","monster");
    static final String[][] BRANDS = {{"paypal","paypal.com"},{"microsoft","microsoft.com,live.com,office.com,microsoftonline.com"},{"google","google.com,gstatic.com"},{"apple","apple.com,icloud.com"},{"amazon","amazon.com,amazon.in"},{"netflix","netflix.com"},{"facebook","facebook.com,fb.com"},{"instagram","instagram.com"},{"sbi","sbi.co.in,onlinesbi.sbi"},{"hdfc","hdfcbank.com"},{"icici","icicibank.com"},{"paytm","paytm.com"},{"dhl","dhl.com"},{"fedex","fedex.com"}};
    static final Object[][] OBF = {{"eval(", "eval\\(", 3, 8}, {"atob(", "atob\\(", 2, 8}, {"unescape(", "unescape\\(", 1, 8}, {"String.fromCharCode", "fromCharCode", 3, 8}, {"document.write(", "document\\.write\\(", 3, 5},
        {"hex escapes (\\x..)", "\\\\x[0-9a-fA-F]{2}", 25, 10}, {"long base64 blob", "[A-Za-z0-9+/]{300,}", 1, 10}, {"string-based setTimeout", "setTimeout\\(\\s*[\"']", 1, 5}};

    static final class Job {
        final String id = UUID.randomUUID().toString().substring(0, 8); final LinkedHashMap<String, String> stages = new LinkedHashMap<>();
        volatile String result; volatile byte[] shot; volatile double[] feats;
        synchronized void stage(String n, String s) { stages.put(n, s); }
        synchronized String json() { StringJoiner j = new StringJoiner(",", "[", "]"); stages.forEach((k, v) -> j.add("{\"name\":" + Json.s(k) + ",\"state\":" + Json.s(v) + "}"));
            return "{\"id\":" + Json.s(id) + ",\"done\":" + (result != null) + ",\"stages\":" + j + ",\"result\":" + (result == null ? "null" : result) + "}"; }
    }
    static final class Fetch { List<String[]> chain = new ArrayList<>(); URI last; int status; String ctype = "", body = "", error; long bytes; HttpHeaders headers; }
    record Tls(boolean ok, String subject, String issuer, String from, String to, long age, boolean expired, String error) {
        String json() { return "{\"ok\":" + ok + ",\"subject\":" + Json.s(subject) + ",\"issuer\":" + Json.s(issuer) + ",\"from\":" + Json.s(from) + ",\"to\":" + Json.s(to) + ",\"ageDays\":" + age + ",\"expired\":" + expired + ",\"error\":" + Json.s(error) + "}"; } }

    static String start(String target) { if (JOBS.size() > 50) JOBS.clear(); Job j = new Job(); JOBS.put(j.id, j); POOL.submit(() -> run(j, target)); return j.id; }
    static boolean blocked(InetAddress a) { byte[] b = a.getAddress();
        return a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress() || a.isSiteLocalAddress() || a.isMulticastAddress() || (b.length == 4 && (b[0] & 255) == 100 && (b[1] & 0xC0) == 64) || (b.length == 16 && (b[0] & 0xFE) == 0xFC); }
    static void checkHost(String host) throws Exception {
        for (InetAddress a : InetAddress.getAllByName(host)) if (!ALLOW_LOCAL && blocked(a)) throw new IllegalArgumentException("Blocked: " + host + " resolves to a private or internal address (" + a.getHostAddress() + "). The scanner only visits public sites.");
    }
    static boolean ipLiteral(String h) { return h.matches("\\d{1,3}(\\.\\d{1,3}){3}") || h.contains(":"); }
    static String reg(String h) { String[] p = h.split("\\."); int n = p.length; if (n <= 2 || ipLiteral(h)) return h; return (p[n - 1].length() == 2 && Set.of("co","com","org","net","gov","ac").contains(p[n - 2]) && n >= 3) ? p[n - 3] + "." + p[n - 2] + "." + p[n - 1] : p[n - 2] + "." + p[n - 1]; }

    static Fetch fetchChain(Job job, URI start, boolean guessed) {
        job.stage("Fetch page and follow redirects", "running"); Fetch f = new Fetch();
        HttpClient c = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(8)).build(); URI cur = start; int hops = 0;
        while (hops < 8) {
            try {
                checkHost(cur.getHost());
                HttpResponse<InputStream> r = c.send(HttpRequest.newBuilder(cur).timeout(Duration.ofSeconds(12)).header("User-Agent", UA).GET().build(), HttpResponse.BodyHandlers.ofInputStream()); hops++;
                String loc = r.headers().firstValue("location").orElse(""); f.chain.add(new String[]{cur.toString(), "" + r.statusCode(), loc});
                f.status = r.statusCode(); f.last = cur; f.headers = r.headers(); f.ctype = r.headers().firstValue("content-type").orElse("");
                if (r.statusCode() >= 300 && r.statusCode() < 400 && !loc.isEmpty()) { r.body().close(); cur = cur.resolve(loc); if (cur.getScheme() == null || !cur.getScheme().startsWith("http")) break; continue; }
                try (InputStream in = r.body()) { byte[] b = in.readNBytes(1_500_000); f.bytes = b.length; if (f.ctype.isEmpty() || f.ctype.contains("html") || f.ctype.contains("text") || f.ctype.contains("javascript")) f.body = new String(b, StandardCharsets.UTF_8); }
                break;
            } catch (Exception e) {
                if (guessed && hops == 0 && cur.getScheme().equals("https")) { guessed = false; cur = URI.create("http" + cur.toString().substring(5)); continue; }
                f.error = e.getClass().getSimpleName() + ": " + e.getMessage(); break;
            }
        }
        job.stage("Fetch page and follow redirects", f.error == null ? "done" : "failed"); return f;
    }
    static Tls tls(String host, int port) {
        try (Socket raw = new Socket()) { raw.connect(new InetSocketAddress(host, port), 6000); raw.setSoTimeout(6000);
            try (SSLSocket s = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(raw, host, port, true)) {
                SSLParameters sp = s.getSSLParameters(); sp.setEndpointIdentificationAlgorithm("HTTPS"); s.setSSLParameters(sp); s.startHandshake();
                X509Certificate c = (X509Certificate) s.getSession().getPeerCertificates()[0];
                return new Tls(true, c.getSubjectX500Principal().getName(), c.getIssuerX500Principal().getName(), "" + c.getNotBefore().toInstant(), "" + c.getNotAfter().toInstant(), Duration.between(c.getNotBefore().toInstant(), Instant.now()).toDays(), c.getNotAfter().before(new Date()), null); }
        } catch (Exception e) { return new Tls(false, null, null, null, null, 0, false, e.getClass().getSimpleName() + ": " + e.getMessage()); }
    }
    static String findBrowser() {
        String o = System.getProperty("scan.browser"); if (o != null) return o; String l = System.getenv("LOCALAPPDATA"); if (l == null) l = "";
        for (String p : new String[]{"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe", l + "\\Google\\Chrome\\Application\\chrome.exe", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
            "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}) try { if (Files.isExecutable(Path.of(p))) return p; } catch (Exception ignored) {}
        return null;
    }
    static Object[] capture(Job job, URI u) {
        String br = findBrowser(); if (br == null) { job.stage(CAP, "skipped"); return null; } job.stage(CAP, "running"); Path tmp = null;
        try {
            tmp = Files.createTempDirectory("scan"); Path png = tmp.resolve("shot.png"), net = tmp.resolve("net.json");
            ProcessBuilder pb = new ProcessBuilder(br, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
                "--disable-extensions", "--disable-background-networking", "--ignore-certificate-errors", "--allow-insecure-localhost",
                "--allow-running-insecure-content", "--disable-web-security", "--no-sandbox",
                "--disable-blink-features=AutomationControlled", "--user-agent=" + UA, "--lang=en-US,en",
                "--user-data-dir=" + tmp.resolve("p"),
                "--window-size=1280,900", "--hide-scrollbars", "--virtual-time-budget=2500", "--log-net-log=" + net, "--screenshot=" + png, u.toString());
            pb.redirectErrorStream(true); pb.redirectOutput(ProcessBuilder.Redirect.DISCARD); Process p = pb.start(); if (!p.waitFor(30, TimeUnit.SECONDS)) p.destroyForcibly();
            byte[] shot = Files.exists(png) ? Files.readAllBytes(png) : null; LinkedHashSet<String> urls = new LinkedHashSet<>();
            if (Files.exists(net)) { Matcher m = Pattern.compile("\"url\":\"(https?://[^\"]{4,300})\"").matcher(Files.readString(net, StandardCharsets.ISO_8859_1)); while (m.find() && urls.size() < 300) urls.add(m.group(1)); }
            job.stage(CAP, shot != null ? "done" : "failed"); return new Object[]{shot, new ArrayList<>(urls)};
        } catch (Exception e) { job.stage(CAP, "failed"); return null; }
        finally { if (tmp != null) try (var w = Files.walk(tmp)) { w.sorted(Comparator.reverseOrder()).forEach(x -> x.toFile().delete()); } catch (Exception ignored) {} }
    }
    static String host(String url) { try { String h = URI.create(url).getHost(); return h == null ? null : h.toLowerCase(Locale.ROOT); } catch (Exception e) { return null; } }
    static int count(String s, String re) { Matcher m = Pattern.compile(re).matcher(s); int n = 0; while (m.find()) n++; return n; }

    static void run(Job job, String target) {
        try {
            job.stage("Check target", "running"); boolean guessed = !target.contains("://");
            URI u = URI.create((guessed ? "https://" : "") + target.trim().replace(" ", "%20"));
            if (u.getHost() == null || !u.getScheme().matches("(?i)https?")) throw new IllegalArgumentException("Enter a valid http(s) URL, domain name or IP address.");
            checkHost(u.getHost()); job.stage("Check target", "done");
            Fetch f = fetchChain(job, u, guessed); List<Json.F> fl = new ArrayList<>();
            URI first = URI.create(f.chain.isEmpty() ? u.toString() : f.chain.get(0)[0]);
            URI finalTarget = f.last != null ? f.last : first;
            Future<Object[]> capF = f.error == null || !f.chain.isEmpty() ? POOL.submit(() -> capture(job, finalTarget)) : null; if (capF == null) job.stage(CAP, "skipped");
            String h0 = first.getHost().toLowerCase(Locale.ROOT), fin = f.last != null ? f.last.getHost().toLowerCase(Locale.ROOT) : h0;
            job.stage("TLS certificate", "running"); Tls t = "https".equals(first.getScheme()) ? tls(fin.equals(h0) ? h0 : fin, 443) : new Tls(false, null, null, null, null, 0, false, "Site does not use HTTPS"); job.stage("TLS certificate", "done");
            // --- URL features
            String full = u.toString().toLowerCase(Locale.ROOT); boolean ipH = ipLiteral(h0), puny = h0.contains("xn--"), noTls = !"https".equals(first.getScheme()), badTld = BAD_TLD.contains(h0.substring(h0.lastIndexOf('.') + 1));
            boolean isLocal = false;
            try { for (InetAddress a : InetAddress.getAllByName(h0)) if (blocked(a)) { isLocal = true; break; } } catch (Exception ignored) {}
            if (isLocal) Json.add(fl, "info", "Internal / private network address", "Target is in a private, loopback, or local IP range.", 0);
            if (ipH && !isLocal) { Json.add(fl, "high", "Address is a raw IP", "Legitimate sites almost always use a domain name.", 15); try { Json.add(fl, "info", "Reverse DNS: " + InetAddress.getByName(h0).getCanonicalHostName(), "", 0); } catch (Exception ignored) {} }
            if (puny) Json.add(fl, "high", "Punycode domain", "Internationalised domains are used for look-alike attacks.", 15);
            if (full.contains("@")) Json.add(fl, "high", "'@' in URL", "Everything before @ is ignored by the browser, a common trick to disguise the real host.", 15);
            if (badTld) Json.add(fl, "medium", "Domain ends in a high-abuse TLD", "." + h0.substring(h0.lastIndexOf('.') + 1) + " is frequently used for throwaway sites.", 10);
            if (noTls) Json.add(fl, "medium", "Not using HTTPS", "Traffic is not encrypted.", 8);
            if (h0.split("\\.").length >= 5 || h0.length() > 40) Json.add(fl, "medium", "Very long or deeply nested hostname", h0, 8);
            if (UrlScan.SHORT().contains(h0)) Json.add(fl, "medium", "URL shortener", "The real destination is hidden behind a redirect.", 8);
            int kw = 0; for (String k : new String[]{"login", "verify", "secure", "update", "account", "signin", "confirm", "wallet", "bank"}) if (full.contains(k)) kw++;
            if (kw >= 2) Json.add(fl, "medium", "Phishing words in URL", kw + " of: login, verify, secure, account, confirm...", 10);
            if (u.getPort() != -1 && u.getPort() != 80 && u.getPort() != 443) Json.add(fl, "low", "Unusual port " + u.getPort(), "", 5);
            if (u.toString().length() > 120) Json.add(fl, "low", "Very long URL", "", 5);
            if (f.chain.size() >= 4) Json.add(fl, "medium", "Long redirect chain (" + f.chain.size() + " hops)", "Chains hide the final destination from filters.", 10);
            if (f.last != null && !reg(fin).equals(reg(h0))) Json.add(fl, "medium", "Redirects to a different domain", h0 + " to " + fin, 8);
            if (f.error != null) Json.add(fl, "info", "Page could not be fetched", f.error, 0);
            boolean tlsBad = false; if ("https".equals(first.getScheme())) { if (!t.ok()) { tlsBad = true; Json.add(fl, "high", "TLS certificate problem", t.error(), 20); }
                else if (t.expired()) { tlsBad = true; Json.add(fl, "high", "Certificate expired", t.to(), 20); } else if (t.age() < 14) { tlsBad = true; Json.add(fl, "medium", "Very new certificate (" + t.age() + " days old)", "Phishing sites often use freshly issued certificates.", 12); } }
            // --- page analysis
            String body = f.body, title = "", lowBody = body.toLowerCase(Locale.ROOT); Matcher tm = Pattern.compile("(?is)<title[^>]*>(.*?)</title>").matcher(body); if (tm.find()) title = tm.group(1).replaceAll("\\s+", " ").trim();
            Map<String, Integer> hosts = new TreeMap<>(); Matcher am = Pattern.compile("(?i)(?:src|href|action)\\s*=\\s*[\"']([^\"'#][^\"']*)[\"']").matcher(body); int dl = 0; URI base = f.last != null ? f.last : first;
            while (am.find()) try { String v = am.group(1).trim(); URI r = base.resolve(v); if (r.getHost() != null && r.getScheme().startsWith("http")) { hosts.merge(r.getHost().toLowerCase(Locale.ROOT), 1, Integer::sum); if (v.toLowerCase(Locale.ROOT).matches(".*\\.(exe|scr|msi|apk|bat|jar|ps1)(\\?.*)?$")) dl++; } } catch (Exception ignored) {}
            List<String> extScripts = new ArrayList<>(); int inline = 0; StringBuilder allJs = new StringBuilder(); Matcher sm = Pattern.compile("(?is)<script\\b([^>]*)>(.*?)</script>").matcher(body);
            while (sm.find()) { Matcher src = Pattern.compile("(?i)src\\s*=\\s*[\"']([^\"']+)[\"']").matcher(sm.group(1)); if (src.find()) try { extScripts.add(base.resolve(src.group(1)).toString()); } catch (Exception ignored) {} else { inline++; allJs.append(sm.group(2)).append('\n'); } }
            List<String> obf = new ArrayList<>(); int obfPts = 0; String js = allJs.toString();
            for (Object[] o : OBF) { int n = count(js, (String) o[1]); if (n >= (int) o[2]) { obf.add(o[0] + " x" + n); obfPts += (int) o[3]; } }
            if (obfPts > 0) Json.add(fl, obfPts >= 15 ? "high" : "medium", "Obfuscated JavaScript techniques", String.join(", ", obf), Math.min(30, obfPts));
            if (Pattern.compile("(?i)(window\\.|document\\.)?location(\\.href)?\\s*=|location\\.replace\\(").matcher(js).find() && inline > 0 && js.length() < 3000) Json.add(fl, "medium", "Script-driven redirect", "Inline script navigates the browser elsewhere.", 8);
            if (Pattern.compile("(?i)<meta[^>]+http-equiv=[\"']?refresh").matcher(body).find()) Json.add(fl, "medium", "Meta refresh redirect", "", 8);
            List<String> iframes = new ArrayList<>(); boolean hiddenFrame = false; Matcher im = Pattern.compile("(?is)<iframe\\b([^>]*)>").matcher(body);
            while (im.find()) { String a = im.group(1).toLowerCase(Locale.ROOT), s = ""; Matcher sr = Pattern.compile("src\\s*=\\s*[\"']([^\"']+)").matcher(a); if (sr.find()) s = sr.group(1); iframes.add(s);
                if (a.matches("(?s).*(width\\s*=\\s*[\"']?0|height\\s*=\\s*[\"']?0|display\\s*:\\s*none|visibility\\s*:\\s*hidden).*")) hiddenFrame = true; }
            if (hiddenFrame) Json.add(fl, "high", "Hidden iframe", "Invisible frames are used to load malware or skimmers.", 20); else if (!iframes.isEmpty()) Json.add(fl, "info", iframes.size() + " iframe(s) on the page", "", 0);
            if (dl > 0) Json.add(fl, "high", "Links to downloadable programs (" + dl + ")", "Executable, installer or APK links.", 15);
            if (f.ctype.contains("octet-stream") || (f.headers != null && f.headers.firstValue("content-disposition").orElse("").contains("attachment"))) Json.add(fl, "high", "Target triggers a file download", "The URL serves a file instead of a web page.", 20);
            StringBuilder forms = new StringBuilder(); boolean pw = false, xform = false; Matcher fm = Pattern.compile("(?is)<form\\b([^>]*)>(.*?)</form>").matcher(body); int nf = 0;
            while (fm.find() && nf++ < 10) { String a = fm.group(1); Matcher ac = Pattern.compile("(?i)action\\s*=\\s*[\"']([^\"']*)").matcher(a); String act = ac.find() ? ac.group(1) : ""; boolean hasPw = Pattern.compile("(?i)type\\s*=\\s*[\"']?password").matcher(fm.group(2)).find(); String ah = null; try { ah = base.resolve(act).getHost(); } catch (Exception ignored) {}
                boolean ext = ah != null && !reg(ah.toLowerCase(Locale.ROOT)).equals(reg(fin)); pw |= hasPw; xform |= ext && hasPw;
                Matcher me = Pattern.compile("(?i)method\\s*=\\s*[\"']?(\\w+)").matcher(a); if (forms.length() > 0) forms.append(','); forms.append("{\"action\":" + Json.s(act) + ",\"method\":" + Json.s(me.find() ? me.group(1) : "get") + ",\"password\":" + hasPw + ",\"external\":" + ext + "}"); }
            if (xform) Json.add(fl, "high", "Login form sends data to another domain", "Typed passwords would leave this site.", 25);
            if (pw && noTls) Json.add(fl, "high", "Password field on an unencrypted page", "", 15); else if (pw) Json.add(fl, "info", "Page contains a login form", "", 0);
            boolean brandBad = false; String tl = title.toLowerCase(Locale.ROOT);
            for (String[] b : BRANDS) if (Pattern.compile("\\b" + b[0] + "\\b").matcher(tl).find()) { boolean ok = false; for (String d : b[1].split(",")) if (fin.equals(d) || fin.endsWith("." + d)) ok = true;
                if (!ok) { brandBad = true; Json.add(fl, "high", "Possible " + b[0] + " impersonation", "Page title mentions " + b[0] + " but the site is " + fin + ".", 25); break; } }
            // --- browser capture result, domains
            Object[] cap = null; try { if (capF != null) cap = capF.get(60, TimeUnit.SECONDS); } catch (Exception ignored) {}
            @SuppressWarnings("unchecked") List<String> reqs = cap != null ? (List<String>) cap[1] : new ArrayList<>(); byte[] shot = cap != null ? (byte[]) cap[0] : null; job.shot = shot;
            for (String r : reqs) { String h = host(r); if (h != null) hosts.merge(h, 1, Integer::sum); }
            if (cap == null) Json.add(fl, "info", "Browser capture not available", "Install Google Chrome or Microsoft Edge to enable screenshots and live network capture.", 0);
            long third = hosts.keySet().stream().filter(h -> !reg(h).equals(reg(fin))).count(); if (third > 15) Json.add(fl, "low", "Contacts many third-party domains (" + third + ")", "Heavy tracking or ad-injection.", 5);
            if (hosts.keySet().stream().anyMatch(h -> ipLiteral(h) && !h.equals(h0))) Json.add(fl, "medium", "Loads resources from a raw IP address", "", 10);
            List<Map.Entry<String, Integer>> hl = new ArrayList<>(hosts.entrySet()); hl.sort((a, b) -> b.getValue() - a.getValue()); if (hl.size() > 15) hl = hl.subList(0, 15);
            Map<String, Future<String>> dns = new LinkedHashMap<>(); for (var e : hl) { String h = e.getKey(); dns.put(h, POOL.submit(() -> { StringJoiner j = new StringJoiner(","); for (InetAddress a : InetAddress.getAllByName(h)) j.add(a.getHostAddress()); return j.toString(); })); }
            StringJoiner doms = new StringJoiner(",", "[", "]");
            for (var e : hl) { String ips = ""; try { ips = dns.get(e.getKey()).get(4, TimeUnit.SECONDS); } catch (Exception ignored) {} String h = e.getKey();
                List<String> flags = new ArrayList<>(); if (ipLiteral(h)) flags.add("raw IP"); if (h.contains("xn--")) flags.add("punycode"); if (BAD_TLD.contains(h.substring(h.lastIndexOf('.') + 1))) flags.add("risky TLD");
                doms.add("{\"host\":" + Json.s(h) + ",\"requests\":" + e.getValue() + ",\"party\":" + Json.s(reg(h).equals(reg(fin)) ? "first-party" : "third-party") + ",\"ips\":" + Json.s(ips) + ",\"flags\":" + Json.strs(flags) + "}"); }
            int sc = Json.score(fl);
            double[] x = {ipH ? 1 : 0, puny ? 1 : 0, noTls ? 1 : 0, badTld ? 1 : 0, Math.min(f.chain.size(), 5) / 5.0, Math.min(obf.size(), 5) / 5.0, pw ? 1 : 0, xform ? 1 : 0, hiddenFrame ? 1 : 0, Math.min(third, 30) / 30.0, brandBad ? 1 : 0, tlsBad ? 1 : 0}; job.feats = x;
            StringJoiner chain = new StringJoiner(",", "[", "]"); for (String[] c : f.chain) chain.add("{\"url\":" + Json.s(c[0]) + ",\"status\":" + Json.s(c[1]) + ",\"location\":" + Json.s(c[2]) + "}");
            StringJoiner hdr = new StringJoiner(",", "{", "}"); if (f.headers != null) for (String k : new String[]{"server", "x-powered-by", "content-security-policy", "strict-transport-security", "x-frame-options", "set-cookie"}) f.headers.firstValue(k).ifPresent(v -> hdr.add(Json.s(k) + ":" + Json.s(v.length() > 120 ? v.substring(0, 120) : v)));
            job.result = "{\"kind\":\"url\",\"id\":" + Json.s(job.id) + ",\"target\":" + Json.s(target) + ",\"finalUrl\":" + Json.s(f.last != null ? f.last.toString() : null) + ",\"title\":" + Json.s(title) + ",\"status\":" + f.status + ",\"contentType\":" + Json.s(f.ctype) + ",\"bytes\":" + f.bytes
                + ",\"score\":" + sc + ",\"verdict\":" + Json.s(Json.verdict(sc)) + ",\"learned\":" + Math.round(MODEL.predict(x) * 100) + ",\"feedbackCount\":" + MODEL.updates() + ",\"findings\":" + Json.findings(fl) + ",\"chain\":" + chain + ",\"tls\":" + t.json() + ",\"headers\":" + hdr
                + ",\"scripts\":{\"external\":" + Json.strs(extScripts) + ",\"inline\":" + inline + ",\"obfuscation\":" + Json.strs(obf) + "},\"iframes\":" + Json.strs(iframes) + ",\"forms\":[" + forms + "],\"domains\":" + doms + ",\"requests\":" + Json.strs(reqs) + ",\"hasShot\":" + (shot != null) + "}";
        } catch (Exception e) { job.result = "{\"kind\":\"error\",\"error\":" + Json.s(e.getMessage() == null ? e.toString() : e.getMessage()) + "}"; }
    }
    static final Set<String> SHORT_SET = Set.of("bit.ly","tinyurl.com","t.co","goo.gl","is.gd","cutt.ly","rb.gy","ow.ly","shorturl.at");
    static Set<String> SHORT() { return SHORT_SET; }
}

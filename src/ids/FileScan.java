package ids;
import java.io.*; import java.nio.charset.StandardCharsets; import java.security.MessageDigest; import java.util.*; import java.util.regex.*; import java.util.zip.*;

/** Static file and message analysis. Nothing is executed or opened; files are only read as bytes. */
final class FileScan {
    static final Set<String> RISKY = Set.of("exe","scr","bat","cmd","com","pif","js","jse","vbs","vbe","wsf","ps1","jar","lnk","hta","msi","iso","dll","apk","docm","xlsm","pptm","reg");
    static final String EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    static final Object[][] STRINGS = {
        {"powershell", 12, "Runs PowerShell"}, {"-encodedcommand", 20, "Encoded PowerShell command"}, {"frombase64string", 15, "Decodes hidden base64 data"},
        {"cmd.exe /c", 15, "Runs shell commands"}, {"wscript.shell", 20, "Windows scripting shell"}, {"autoopen", 25, "Macro runs on open"},
        {"document_open", 25, "Macro runs on open"}, {"workbook_open", 25, "Macro runs on open"}, {"invoke-expression", 15, "Runs text as code"},
        {"downloadstring", 20, "Downloads and runs remote code"}, {"downloadfile", 18, "Downloads a file"}, {"urlmon", 10, "Downloader API"},
        {"createremotethread", 30, "Process injection API"}, {"mimikatz", 40, "Credential-stealing tool name"}, {"unescape(", 8, "Obfuscated script"}};

    static String magic(byte[] d) {
        if (d.length < 4) return "Empty or tiny file";
        String h = new String(d, 0, Math.min(8, d.length), StandardCharsets.ISO_8859_1);
        if (h.startsWith("MZ")) return "Windows executable (PE)"; if (h.startsWith("%PDF")) return "PDF document";
        if (h.startsWith("PK\3\4")) return "ZIP-based (ZIP, Office, JAR, APK)"; if ((d[0] & 255) == 0xD0 && (d[1] & 255) == 0xCF) return "Legacy Office (OLE)";
        if (h.startsWith("\u007fELF")) return "Linux executable (ELF)"; if (h.startsWith("Rar!")) return "RAR archive"; if (h.startsWith("7z")) return "7-Zip archive";
        if (h.startsWith("GIF8")) return "GIF image"; if ((d[0] & 255) == 0x89 && h.startsWith("\u0089PNG")) return "PNG image"; if ((d[0] & 255) == 0xFF && (d[1] & 255) == 0xD8) return "JPEG image";
        if (h.startsWith("{\\rtf")) return "RTF document"; if (h.startsWith("#!")) return "Script (shebang)";
        int printable = 0, n = Math.min(d.length, 4096); for (int i = 0; i < n; i++) { int c = d[i] & 255; if (c == 9 || c == 10 || c == 13 || (c >= 32 && c < 127)) printable++; }
        return printable > n * 0.9 ? "Text / script / HTML" : "Unknown binary";
    }
    static double entropy(byte[] d) { long[] c = new long[256]; for (byte b : d) c[b & 255]++; double e = 0; for (long x : c) if (x > 0) { double p = (double) x / d.length; e -= p * Math.log(p) / Math.log(2); } return e; }
    static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x)); return s.toString(); }
    static List<String> urls(String t) { LinkedHashSet<String> u = new LinkedHashSet<>(); Matcher m = Pattern.compile("https?://[^\\s\"'<>\\\\)]{4,200}").matcher(t); while (m.find() && u.size() < 25) u.add(m.group()); return new ArrayList<>(u); }

    static String scanFile(String name, byte[] d) throws Exception {
        List<Json.F> f = new ArrayList<>(); String lower = name.toLowerCase(Locale.ROOT); String ext = lower.contains(".") ? lower.substring(lower.lastIndexOf('.') + 1) : "";
        String type = magic(d); boolean exe = type.contains("executable"); double ent = entropy(d);
        String text = new String(d, 0, Math.min(d.length, 4_000_000), StandardCharsets.ISO_8859_1), low = text.toLowerCase(Locale.ROOT);
        if (text.contains(EICAR)) Json.add(f, "high", "EICAR antivirus test file", "This is the standard harmless test string that antivirus tools detect. It is not real malware.", 100);
        if (exe && !RISKY.contains(ext)) Json.add(f, "high", "Executable disguised as ." + (ext.isEmpty() ? "(none)" : ext), "File content is a " + type + " but the name suggests something else.", 45);
        Map<String, String> want = Map.of("jpg", "JPEG", "jpeg", "JPEG", "png", "PNG", "gif", "GIF", "pdf", "PDF", "docx", "ZIP", "xlsx", "ZIP", "zip", "ZIP", "doc", "OLE", "xls", "OLE");
        if (want.containsKey(ext) && !type.contains(want.get(ext)) && !exe) Json.add(f, "medium", "File type does not match its extension", "Extension ." + ext + " but content looks like: " + type + ".", 20);
        if (lower.matches(".*\\.(pdf|docx?|xlsx?|jpe?g|png|txt)\\.(exe|scr|bat|cmd|js|vbs|ps1|lnk|hta)$")) Json.add(f, "high", "Double extension", "The name hides the real file type: " + name, 40);
        if (name.contains("\u202e")) Json.add(f, "high", "Right-to-left override in file name", "This trick reverses part of the name to hide the real extension.", 40);
        if (RISKY.contains(ext)) Json.add(f, "medium", "Risky file type (." + ext + ")", "This type can run code or contain macros.", 15);
        for (Object[] s : STRINGS) if (low.contains((String) s[0])) Json.add(f, (int) s[1] >= 20 ? "high" : "medium", "Suspicious content: " + s[0], (String) s[2], (int) s[1]);
        if (low.contains("virtualalloc") && low.contains("writeprocessmemory")) Json.add(f, "high", "Memory-injection APIs", "Imports commonly used by malware loaders.", 25);
        if (ent > 7.4 && d.length > 20000 && (exe || type.startsWith("Unknown"))) Json.add(f, "medium", "Very high entropy (" + String.format(Locale.ROOT, "%.2f", ent) + ")", "Packed or encrypted content is common in malware.", 15);
        List<String> entries = new ArrayList<>();
        if (type.startsWith("ZIP")) try (ZipInputStream z = new ZipInputStream(new ByteArrayInputStream(d))) {
            ZipEntry e; while ((e = z.getNextEntry()) != null && entries.size() < 200) entries.add(e.getName()); // names only: nothing is extracted
        } catch (Exception ignored) {}
        for (String e : entries) { String l = e.toLowerCase(Locale.ROOT);
            if (l.endsWith("vbaproject.bin")) Json.add(f, "high", "Contains VBA macros", "Entry: " + e, 30);
            else if (l.matches(".*\\.(exe|scr|bat|cmd|js|vbs|ps1|dll|lnk|hta)$")) Json.add(f, "high", "Archive contains an executable or script", "Entry: " + e, 25); }
        List<String> urls = urls(text); if (urls.size() > 10) Json.add(f, "low", "Many embedded URLs (" + urls.size() + "+)", "Scan them individually on the website tab.", 5);
        int sc = Json.score(f);
        return "{\"kind\":\"file\",\"name\":" + Json.s(name) + ",\"size\":" + d.length + ",\"type\":" + Json.s(type) + ",\"entropy\":" + String.format(Locale.ROOT, "%.2f", ent)
            + ",\"sha256\":\"" + hex(MessageDigest.getInstance("SHA-256").digest(d)) + "\",\"md5\":\"" + hex(MessageDigest.getInstance("MD5").digest(d)) + "\",\"score\":" + sc + ",\"verdict\":" + Json.s(Json.verdict(sc))
            + ",\"findings\":" + Json.findings(f) + ",\"urls\":" + Json.strs(urls) + ",\"entries\":" + Json.strs(entries) + "}";
    }

    static int hits(String low, String lowNorm, String... w) {
        int n = 0;
        for (String x : w) if (low.contains(x) || lowNorm.contains(x)) n++;
        return n;
    }

    /** Adds one finding for a scam category and returns number of matched phrases. */
    static int cat(List<Json.F> f, String low, String lowNorm, String title, String detail, int per, int cap, String... w) {
        int h = hits(low, lowNorm, w);
        if (h == 0) return 0;
        int pts = Math.min(cap, h * per);
        Json.add(f, pts >= 20 ? "high" : "medium", title + " (" + h + " phrase" + (h > 1 ? "s" : "") + ")", detail, pts);
        return h;
    }

    static String scanText(String t) {
        List<Json.F> f = new ArrayList<>();
        String low = t.toLowerCase(Locale.ROOT).replaceAll("[\"'\u201c\u201d\u2018\u2019]", "");
        String lowNorm = low.replaceAll("[-_./,;:!?()]+", " ").replaceAll("\\s+", " ");
        int cats = 0;

        // 1. Advance-Fee / Upfront payment demands (Hallmark of job, delivery & lottery fraud)
        int hFee = cat(f, low, lowNorm, "Advance-fee or upfront payment demand",
            "Legitimate employers, carriers, lotteries, and platforms never ask you to pay registration, security, rescheduling, or processing fees.",
            8, 24,
            "registration fee", "processing fee", "security fee", "refundable fee", "refundable deposit", "security deposit",
            "joining fee", "enrollment fee", "reschedule fee", "delivery fee", "shipping fee", "redelivery fee", "handling fee",
            "clearance charge", "clearance fee", "pay fee", "pay a fee", "pay registration", "pay to secure", "fee to secure",
            "secure your position", "secure your seat", "advance fee", "upfront fee", "upfront payment", "pay upfront",
            "initial deposit", "deposit amount", "send money", "transfer money", "pay rs", "transfer rs", "pay in advance",
            "payment required", "wire money", "nominal fee", "small fee", "pay to reschedule", "pay to receive", "pay to claim");
        
        // Detect fee / charge patterns like "Pay ₹25", "Pay Rs 50", "Pay $5", "Pay 25 to reschedule"
        boolean hasPayAmount = Pattern.compile("(?i)\\b(?:pay|send|transfer|deposit)\\s*(?:\\u20b9|rs\\.?|inr|\\$|usd|\\u20ac|\\u00a3)?\\s*\\d+").matcher(t).find()
            && hits(low, lowNorm, "reschedule", "delivery", "parcel", "package", "fee", "to receive", "to secure", "registration", "deposit", "charge", "unlock", "release", "shipment") > 0;
        if (hasPayAmount && hFee == 0) {
            hFee++;
            Json.add(f, "high", "Advance-fee or payment demand", "Demands an upfront payment or fee to release, reschedule, or process an item.", 20);
        }
        if (hFee > 0) cats++;

        // 2. Money, Prize or Lottery bait
        int hPrize = cat(f, low, lowNorm, "Money or prize bait",
            "Unexpected winnings, lottery claims, and investment promises are classic spam lures.",
            8, 24,
            "congratulations", "congrats", "you have won", "you won", "won a", "cash prize", "cash reward", "instant cash",
            "lottery", "special lottery", "prize", "winner", "claim your", "claim reward", "claim your reward", "claim now",
            "claim prize", "receive the prize", "receive prize", "receive your prize", "receive reward", "special prize",
            "free gift", "free voucher", "gift voucher", "inheritance", "million", "crore", "lakh", "bitcoin", "crypto",
            "double your", "guaranteed returns", "cashback", "jackpot", "lucky winner", "lucky draw", "pre-approved",
            "pre approved", "loan approved", "trading profit", "high returns", "bonus", "selected for a special lottery",
            "number has been selected", "mobile number has been selected");
        if (hPrize > 0) cats++;

        // 3. Fake job or work-from-home wording
        int hJob = cat(f, low, lowNorm, "Job or work-from-home scam wording",
            "Fake job offers promise easy money for little work. Real employers do not recruit by cold text or demand upfront payments.",
            6, 18,
            "selected for a", "selected for", "you are selected", "hired for", "work from home", "work-from-home", "wfh",
            "part time", "part-time", "full time", "full-time", "job offer", "employment offer", "job vacancy", "job opportunity",
            "daily salary", "monthly salary", "salary of", "salary:", "salary -", "income of", "online job", "remote job",
            "no experience", "no investment", "earn money", "earn rs", "per day", "daily income", "daily earning", "vacancy",
            "data entry", "typing job", "online reviewers", "like videos", "commission", "minutes a day", "hours a day",
            "from home", "mobile phone", "easy task", "simple task", "immediate placement", "offer letter", "guaranteed job");
        if (hJob > 0) cats++;

        // 4. Credential & sensitive personal / financial data harvesting
        int hCreds = cat(f, low, lowNorm, "Asks for credentials or sensitive personal data",
            "Legitimate entities never ask for passwords, OTPs, PINs, bank details, card numbers, or personal identity details by unverified message.",
            11, 25,
            "bank details", "banking details", "account details", "card details", "sharing your bank", "share your bank",
            "share bank details", "send your bank", "send bank details", "bank account", "account number", "credit card",
            "debit card", "atm card", "net banking", "netbanking", "upi pin", "mpin", "secret pin", "pin ", "pin number",
            "password", "otp", "cvv", "passcode", "verification code", "security code", "personal information", "personal details",
            "personal info", "personal data", "provide your personal", "provide your", "share your personal", "contact us and provide",
            "identity details", "id proof", "verification details", "identity information", "sensitive information",
            "aadhaar", "pan card", "kyc", "update your kyc", "login credentials", "id and password", "share details", "send details",
            "share your info", "confirm credentials");
        if (hCreds > 0) cats++;

        // 5. Pressure and urgency language
        int hUrgent = cat(f, low, lowNorm, "Pressure and urgency language",
            "Scams push you to act hastily before you have time to think or verify.",
            7, 16,
            "urgent", "immediately", "act now", "right now", "within 24 hours", "final notice", "last chance", "expires",
            "suspended", "account suspended", "account blocked", "deactivated", "unusual activity", "verify your account",
            "confirm your identity", "limited slots", "limited seats", "hurry", "today only", "offer ends", "dont miss",
            "immediate joining", "immediate action required", "within 1 hour", "respond immediately", "promptly");
        if (hUrgent > 0) cats++;

        // 6. Calls to action & redirection
        int hCta = cat(f, low, lowNorm, "Pushes you to reply, click or join",
            "Calls to action are how scammers move you to unmonitored chat channels, fraudulent forms, or phishing sites.",
            5, 12,
            "reply yes", "reply y ", "reply 1", "click here", "click the link", "tap the link", "using this link", "this link",
            "unknown link", "click link", "visit link", "link below", "join now", "join our", "join the group", "whatsapp",
            "telegram", "dm us", "contact hr", "contact us", "contact our", "reach out to", "call now", "call us", "text back",
            "register now", "apply now", "sign up now", "send message", "click below", "tap here", "claim your", "claim now",
            "share your", "share bank");
        if (hCta > 0) cats++;

        // 7. Fake delivery or package smishing wording
        int hDelivery = cat(f, low, lowNorm, "Package delivery smishing wording",
            "Fake courier or postal notifications claim a delivery failed or is on hold to trick victims into paying redelivery fees or entering cards on phishing pages.",
            8, 22,
            "parcel delivery", "package delivery", "delivery has failed", "delivery failed", "delivery failure", "reschedule delivery",
            "failed delivery", "unsuccessful delivery", "address incomplete", "incomplete address", "package on hold", "parcel on hold",
            "shipment pending", "delivery pending", "package pending", "parcel pending", "customs fee", "customs clearance",
            "update delivery address", "delivery attempt", "reschedule your delivery", "courier delivery", "parcel", "package",
            "reschedule", "redelivery");
        if (hDelivery > 0) cats++;

        // 8. Accidental transfer or payment reversal scam wording
        int hMistake = cat(f, low, lowNorm, "Accidental transfer or UPI reversal lure",
            "Claims of mistakenly sent funds demanding an immediate return via UPI or account transfer are classic fraud tactics (using spoofed SMS or fraudulent collect requests).",
            10, 26,
            "accidentally transferred", "transferred money to your account", "transferred money", "accidentally sent",
            "transferred by mistake", "sent by mistake", "mistakenly sent", "mistakenly transferred", "wrongly transferred",
            "wrongly credited", "credited by mistake", "return it", "return the money", "return money", "send it back",
            "send back", "refund the money", "refund it", "transfer it back", "reverse the transaction", "return immediately",
            "upi id", "upi handle", "vpa", "gpay", "phonepe", "paytm", "google pay");
        if (hMistake > 0) cats++;

        // 9. Specific earnings promise
        boolean hasEarnings = Pattern.compile("(?i)(\\u20b9|rs\\.?\\s?|inr\\s?|\\$|usd\\s?|\\u20ac|\\u00a3)\\s?\\d[\\d,]*").matcher(t).find()
            && hits(low, lowNorm, "daily", "per day", "a day", "per hour", "weekly", "per week", "monthly", "per month", "earn") > 0;
        if (hasEarnings) {
            cats++;
            Json.add(f, "high", "Specific earnings promise", "Quoting an exact amount you can earn per day or month is a hallmark of job and investment scams.", 16);
        }

        // 10. High-Risk Compound Scam Synergy (Hallmark cross-category fraud detection)
        if ((hJob > 0 || hasEarnings) && hFee > 0) {
            Json.add(f, "high", "High-Risk Compound Scam: Advance-fee recruitment fraud",
                "The message pairs a lucrative employment offer with a demand for an upfront fee or deposit to secure the position. Real employers never charge applicants.", 28);
        }
        if (hPrize > 0 && hCreds > 0) {
            Json.add(f, "high", "High-Risk Compound Scam: Prize bait with personal data harvesting",
                "The message promises lottery winnings or special rewards while demanding personal, banking, or identity information. This is an unmistakable credential phishing attack.", 32);
        }
        if (hDelivery > 0 && (hFee > 0 || hasPayAmount)) {
            Json.add(f, "high", "High-Risk Compound Scam: Delivery fee smishing attack",
                "Claims an urgent package delivery failure and demands a payment or fee to reschedule. This smishing tactic steals card credentials through fake tracking portals.", 28);
        }
        if (hDelivery > 0 && hits(low, lowNorm, "link", "unknown link", "click link", "visit link", "this link") > 0) {
            Json.add(f, "high", "High-Risk Delivery Smishing: Directs to unverified external link",
                "Combines package delivery issues with links to unverified portals designed to collect personal and payment data.", 15);
        }
        if (hMistake > 0 && (hits(low, lowNorm, "accidentally", "mistake", "wrongly", "credited") > 0 || hUrgent > 0 || hits(low, lowNorm, "return", "refund", "upi") > 0)) {
            Json.add(f, "high", "High-Risk Compound Scam: Accidental transfer / UPI reversal fraud",
                "The sender claims to have mistakenly transferred money and urges you to return funds to an external UPI ID or account. Scammers use spoofed credit notifications or fraudulent reversal requests to steal money.", 36);
        }
        if (hMistake > 0 && hits(low, lowNorm, "upi id", "upi", "vpa", "gpay", "phonepe", "paytm", "to this upi") > 0) {
            cats++;
            Json.add(f, "high", "Directs payment to external UPI handle",
                "Demands funds transfer to an unverified third-party payment identifier.", 14);
        }
        if (hUrgent > 0 && hCreds > 0) {
            Json.add(f, "high", "High-Risk Compound Scam: Urgent account takeover phishing",
                "High-pressure threats of suspension or deactivation combined with requests for credentials, OTPs, or banking details.", 26);
        }
        if (hPrize > 0 && hFee > 0) {
            Json.add(f, "high", "High-Risk Compound Scam: Advance-fee lottery fraud",
                "Demands a processing fee or clearance charge to release an alleged cash prize or reward.", 26);
        }

        // URL analysis
        List<String> urls = urls(t);
        Matcher bare = Pattern.compile("(?i)(?<![@\\w.-])(?:[a-z0-9-]+\\.)+(?:com|in|net|org|xyz|top|click|link|info|online|site|co|me|ly|gl|cc|app|shop|club|live|vip|store)\\b(?:/\\S*)?").matcher(t);
        if (urls.isEmpty() && bare.find()) {
            cats++;
            urls.add(bare.group());
            Json.add(f, "medium", "Contains a website address", "Unsolicited links should not be opened. Scan it on the Website tab first: " + bare.group(), 10);
        }
        for (String x : urls) {
            String h = x.replaceAll("(?i)^https?://", "").split("[/:?]")[0].toLowerCase(Locale.ROOT);
            if (UrlScan.SHORT().contains(h)) Json.add(f, "medium", "Shortened link", h + " hides the real destination.", 10);
            if (h.matches("\\d{1,3}(\\.\\d{1,3}){3}")) Json.add(f, "high", "Link points to a raw IP address", x, 15);
        }
        Matcher a = Pattern.compile("(?is)<a\\s[^>]*href=[\"']https?://([^/\"']+)[^>]*>\\s*(?:https?://)?([a-z0-9.-]+\\.[a-z]{2,})[^<]*</a>").matcher(t);
        while (a.find()) {
            if (!a.group(1).toLowerCase(Locale.ROOT).contains(a.group(2).toLowerCase(Locale.ROOT))) {
                Json.add(f, "high", "Link text does not match its destination", "Shows " + a.group(2) + " but goes to " + a.group(1), 25);
                break;
            }
        }

        long letters = t.chars().filter(Character::isLetter).count(), caps = t.chars().filter(Character::isUpperCase).count();
        if (letters > 40 && caps > letters * 0.3) Json.add(f, "low", "Excessive capital letters", "Shouting text is typical of spam.", 6);
        if (t.chars().filter(ch -> ch == '!').count() >= 3) Json.add(f, "low", "Many exclamation marks", "", 4);

        if (cats >= 3) Json.add(f, "high", "Several scam signals together (" + cats + " kinds)", "Each signal alone can be innocent. Together they match the pattern of scam messages.", cats >= 5 ? 12 : 8);
        else if (cats == 2) Json.add(f, "medium", "Multiple suspicious indicators", "The message exhibits multiple traits commonly found in unsolicited spam and scam campaigns.", 5);

        int raw = 0; for (Json.F item : f) raw += item.pts();
        // Calibrate so high-confidence heuristic scans land realistically in the 85-94 range rather than always flat 100
        int sc = raw > 93 ? 90 + Math.min(4, (raw - 90) / 4) : raw;
        String verdict;
        if (sc >= 75) verdict = "High-risk scam or phishing";
        else if (sc >= 60) verdict = "Likely spam or phishing";
        else if (sc >= 25) verdict = "Suspicious message";
        else if (sc > 0) verdict = "Low-risk cues detected";
        else verdict = "No spam signals found";

        return "{\"kind\":\"text\",\"score\":" + sc + ",\"verdict\":" + Json.s(verdict) + ",\"findings\":" + Json.findings(f) + ",\"urls\":" + Json.strs(urls) + "}";
    }
}

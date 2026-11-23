package ids;
import java.io.*;
import java.nio.file.*;
import java.util.*;

/** Network flow generator. Automatically uses real flows from CIC-IDS2017 if data/cicids2017_real_flows.csv exists; otherwise falls back to synthetic profiles. */
public class DataGen {
    public static final String[] CLASSES = {"Normal", "DoS", "DDoS", "PortScan", "BruteForce", "SQLInjection", "Botnet", "Exfiltration"};
    public static final String[] FEATURES = {"duration", "srcBytes", "dstBytes", "connCount", "sameSrvRate", "errorRate", "failedLogins", "uniquePorts", "srcIPs", "payloadEntropy"};
    static final double[][] BASE = {
        {2.0, 5.0, 5.0, 1.5, 0.8, 0.05, 0.0, 1.0, 1.0, 3.0},  // Normal
        {0.5, 3.0, 1.0, 5.0, 0.9, 0.70, 0.0, 1.0, 1.0, 2.0},  // DoS: one source floods
        {0.5, 3.0, 1.0, 5.5, 0.9, 0.70, 0.0, 1.0, 6.0, 2.0},  // DDoS: many sources flood
        {0.7, 2.0, 1.0, 3.0, 0.3, 0.50, 0.0, 5.0, 1.0, 2.0},  // PortScan: many ports probed
        {1.5, 3.0, 2.0, 2.5, 0.5, 0.20, 4.0, 1.5, 1.0, 3.0},  // BruteForce: failed logins
        {1.0, 6.0, 4.0, 1.5, 0.6, 0.30, 0.5, 1.0, 1.0, 6.0},  // SQLInjection: odd web payloads
        {2.5, 2.5, 2.5, 2.0, 0.7, 0.10, 0.0, 2.0, 2.0, 5.0},  // Botnet: periodic beaconing
        {3.0, 2.0, 8.0, 1.5, 0.7, 0.05, 0.2, 1.5, 1.0, 6.5}}; // Exfiltration: big outbound data

    // In-memory pool of real network flows loaded from CIC-IDS2017
    static final List<Sample>[] REAL_POOL = new List[CLASSES.length];
    static boolean isRealLoaded = false;
    static int realTotalCount = 0;

    static {
        loadRealDataset();
    }

    @SuppressWarnings("unchecked")
    public static synchronized void loadRealDataset() {
        for (int i = 0; i < CLASSES.length; i++) REAL_POOL[i] = new ArrayList<>();
        realTotalCount = 0;
        Path p = Path.of("data/cicids2017_real_flows.csv");
        if (!Files.exists(p)) {
            p = Path.of("e:/Projects/CyberProtector/data/cicids2017_real_flows.csv");
        }
        if (Files.exists(p)) {
            try (BufferedReader br = Files.newBufferedReader(p)) {
                String line = br.readLine(); // skip header
                Map<String, Integer> classMap = new HashMap<>();
                for (int i = 0; i < CLASSES.length; i++) classMap.put(CLASSES[i].toLowerCase(Locale.ROOT), i);

                while ((line = br.readLine()) != null) {
                    String[] parts = line.split(",");
                    if (parts.length < FEATURES.length + 1) continue;
                    String label = parts[parts.length - 1].trim().toLowerCase(Locale.ROOT);
                    Integer clsIdx = classMap.get(label);
                    if (clsIdx == null) continue;

                    double[] x = new double[FEATURES.length];
                    for (int f = 0; f < FEATURES.length; f++) {
                        try {
                            x[f] = Double.parseDouble(parts[f].trim());
                        } catch (Exception ex) {
                            x[f] = 0.0;
                        }
                    }
                    REAL_POOL[clsIdx].add(new Sample(x, clsIdx));
                    realTotalCount++;
                }
                isRealLoaded = realTotalCount > 0;
            } catch (Exception ignored) {}
        }
    }

    public static boolean isRealData() { return isRealLoaded && realTotalCount > 0; }
    public static int getRealCount() { return realTotalCount; }

    final Random rnd; final double[][] mean; final int[] order; final int phase; final double noise, driftRate;

    public DataGen(long seed, int[] attacks, int phase, double noise, double driftRate) {
        rnd = new Random(seed); this.phase = phase; this.noise = noise; this.driftRate = driftRate;
        order = new int[attacks.length + 1]; System.arraycopy(attacks, 0, order, 1, attacks.length);
        mean = new double[BASE.length][];
        for (int c = 0; c < BASE.length; c++) { mean[c] = BASE[c].clone(); for (int i = 0; i < mean[c].length; i++) mean[c][i] += rnd.nextGaussian() * 0.35; }
    }
    public int[] order() { return order; }
    /** How many classes (Normal + attacks) exist at this step: a new attack type appears every `phase` steps. */
    public int active(int step) { return Math.min(order.length, 2 + step / phase); }
    public double drift(int step) { int ds = phase * (order.length - 1); return step < ds ? 0 : (step - ds + 1) * driftRate; }

    public Sample one(int cls, int step) {
        if (isRealLoaded && REAL_POOL[cls] != null && !REAL_POOL[cls].isEmpty()) {
            Sample base = REAL_POOL[cls].get(rnd.nextInt(REAL_POOL[cls].size()));
            double[] x = base.x().clone();
            double d = drift(step);
            // Apply subtle realistic noise and temporal drift to real traffic
            for (int i = 0; i < x.length; i++) {
                x[i] += rnd.nextGaussian() * (noise * 0.08) + d * (i % 2 == 0 ? 0.03 : -0.03);
            }
            return new Sample(x, cls);
        }
        // Fallback to Gaussian generator if real sample pool is not populated
        double[] x = new double[FEATURES.length]; double d = drift(step);
        for (int i = 0; i < x.length; i++) x[i] = mean[cls][i] + rnd.nextGaussian() * noise + d * (i % 2 == 0 ? 1 : -1);
        return new Sample(x, cls);
    }
    /** Stream: mostly the newest attack type, so a learner without memory forgets older ones. */
    public List<Sample> trainBatch(int n, int step) {
        int k = active(step); List<Sample> out = new ArrayList<>();
        for (int i = 0; i < n; i++) out.add(one(order[rnd.nextDouble() < 0.9 ? k - 1 : rnd.nextInt(k)], step));
        return out;
    }
    public List<Sample> testSet(int perClass, int step) {
        List<Sample> out = new ArrayList<>();
        for (int j = 0; j < active(step); j++) for (int i = 0; i < perClass; i++) out.add(one(order[j], step));
        return out;
    }
    public Sample random(int step) { return one(order[rnd.nextInt(active(step))], step); }
}

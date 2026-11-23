package ids;
import java.util.*;
/** Online softmax-regression IDS. With replay=true it keeps a per-class reservoir and rehearses old attacks (experience replay). */
public class Classifier {
    final int F = DataGen.FEATURES.length, C = DataGen.CLASSES.length;
    final double[][] w = new double[C][F + 1];
    final boolean replay; final double lr; final int cap;
    final boolean[] seen = new boolean[C];
    final long[] count = new long[C];
    final List<Sample>[] buf;
    final double[] mean = new double[F], m2 = new double[F]; long n = 0;
    final Random rnd = new Random();

    @SuppressWarnings("unchecked")
    public Classifier(boolean replay, double lr, int cap) {
        this.replay = replay; this.lr = lr; this.cap = cap;
        buf = new List[C];
        for (int i = 0; i < C; i++) buf[i] = new ArrayList<>();
    }

    double[] norm(double[] x) {
        double[] z = new double[F + 1];
        for (int i = 0; i < F; i++) z[i] = n < 2 ? x[i] : (x[i] - mean[i]) / Math.sqrt(m2[i] / n + 1e-6);
        z[F] = 1; return z;
    }
    double[] probs(double[] z) {
        double[] s = new double[C]; double max = -1e18;
        for (int c = 0; c < C; c++) {
            if (!seen[c]) { s[c] = -1e18; continue; }
            double a = 0; for (int i = 0; i <= F; i++) a += w[c][i] * z[i];
            s[c] = a; max = Math.max(max, a);
        }
        double sum = 0;
        for (int c = 0; c < C; c++) { s[c] = seen[c] ? Math.exp(s[c] - max) : 0; sum += s[c]; }
        for (int c = 0; c < C; c++) s[c] /= sum;
        return s;
    }
    public synchronized int predict(double[] x) {
        if (n == 0) return 0;
        double[] p = probs(norm(x)); int b = 0;
        for (int c = 1; c < C; c++) if (p[c] > p[b]) b = c;
        return b;
    }
    public synchronized void learn(List<Sample> batch) {
        for (Sample s : batch) { // running standardisation (Welford-style, no forgetting)
            n++; for (int i = 0; i < F; i++) { double d = s.x()[i] - mean[i]; mean[i] += d / n; m2[i] += d * (s.x()[i] - mean[i]); }
            seen[s.y()] = true; count[s.y()]++;
            List<Sample> b = buf[s.y()];
            if (b.size() < cap) b.add(s); else { long j = (long) (rnd.nextDouble() * count[s.y()]); if (j < cap) b.set((int) j, s); }
        }
        List<Sample> train = new ArrayList<>(batch);
        if (replay) for (int i = 0; i < batch.size(); i++) { // class-balanced rehearsal
            int c; do { c = rnd.nextInt(C); } while (!seen[c] || buf[c].isEmpty());
            train.add(buf[c].get(rnd.nextInt(buf[c].size())));
        }
        for (int epoch = 0; epoch < 3; epoch++) {
            Collections.shuffle(train, rnd);
            for (Sample s : train) {
                double[] z = norm(s.x()), p = probs(z);
                for (int c = 0; c < C; c++) {
                    if (!seen[c]) continue;
                    double g = p[c] - (c == s.y() ? 1 : 0);
                    for (int i = 0; i <= F; i++) w[c][i] -= lr * (g * z[i] + 1e-4 * w[c][i]);
                }
            }
        }
    }
    public synchronized double[] recall(List<Sample> test, int classes) {
        int[] ok = new int[C], tot = new int[C];
        for (Sample s : test) { tot[s.y()]++; if (predict(s.x()) == s.y()) ok[s.y()]++; }
        double[] r = new double[C];
        for (int c = 0; c < C; c++) r[c] = c < classes && tot[c] > 0 ? (double) ok[c] / tot[c] : -1;
        return r;
    }
}

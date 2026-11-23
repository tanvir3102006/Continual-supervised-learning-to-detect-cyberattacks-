package ids;
/** Online logistic regression over scan features. Starts from sensible weights and keeps learning from user feedback (continual supervised learning). */
final class RiskModel {
    final double[] w = {1.2, 1.2, .6, .8, .6, 1.0, .4, 1.5, 1.2, .5, 1.5, 1.0}; double b = -2.4; int updates;
    synchronized double predict(double[] x) { double z = b; for (int i = 0; i < w.length; i++) z += w[i] * x[i]; return 1 / (1 + Math.exp(-z)); }
    synchronized void learn(double[] x, int y) { double g = predict(x) - y; for (int i = 0; i < w.length; i++) w[i] -= 0.4 * g * x[i]; b -= 0.4 * g; updates++; }
    synchronized int updates() { return updates; }
}

package org.example.multimedia_file_security;

import org.example.multimedia_file_security.utils.HyperchaoticChenOptimizedUtil;
import org.example.multimedia_file_security.utils.HyperchaoticChenUtil;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class LyapunovExponentTest {

    @Test
    public void testCalculateLyapunovExponentsDefaultConfig() {
        double[] exponents = HyperchaoticChenUtil.calculateLyapunovExponents();

        assertEquals(4, exponents.length, "Lyapunov exponents array should have length 4");

        assertTrue(exponents[0] >= exponents[1], "First exponent should be >= second");
        assertTrue(exponents[1] >= exponents[2], "Second exponent should be >= third");
        assertTrue(exponents[2] >= exponents[3], "Third exponent should be >= fourth");

        int positiveCount = 0;
        for (double exp : exponents) {
            if (exp > 0) {
                positiveCount++;
            }
        }
        assertTrue(positiveCount >= 2, "Hyperchaotic system should have at least two positive Lyapunov exponents");

        double sum = 0;
        for (double exp : exponents) {
            sum += exp;
        }
        assertTrue(sum < 0, "Dissipative system must have negative sum of Lyapunov exponents, got sum=" + sum);

        System.out.println("Default config Lyapunov exponents (sorted):");
        for (int i = 0; i < exponents.length; i++) {
            System.out.printf("λ%d: %.6f%n", i + 1, exponents[i]);
        }
        System.out.println("Positive exponents count: " + positiveCount);
        System.out.printf("Sum of exponents: %.6f (expected ≈ -25.5)%n", sum);
    }

    @Test
    public void testCalculateOptimizedLyapunovExponentsDefaultConfig() {
        double[] stdExponents = HyperchaoticChenUtil.calculateLyapunovExponents();
        double[] optExponents = HyperchaoticChenOptimizedUtil.calculateLyapunovExponents();

        assertEquals(4, optExponents.length, "Lyapunov exponents array should have length 4");

        assertTrue(optExponents[0] >= optExponents[1], "First exponent should be >= second");
        assertTrue(optExponents[1] >= optExponents[2], "Second exponent should be >= third");
        assertTrue(optExponents[2] >= optExponents[3], "Third exponent should be >= fourth");

        int positiveCount = 0;
        for (double exp : optExponents) {
            if (exp > 0) {
                positiveCount++;
            }
        }
        assertTrue(positiveCount >= 2, "Hyperchaotic system should have at least two positive Lyapunov exponents");

        double sum = 0;
        for (double exp : optExponents) {
            sum += exp;
        }
        assertTrue(sum < 0, "Dissipative system must have negative sum of Lyapunov exponents, got sum=" + sum);

        assertTrue(optExponents[0] > stdExponents[0],
                "Optimized λ1 should be larger than standard λ1");
        assertTrue(optExponents[1] > stdExponents[1],
                "Optimized λ2 should be larger than standard λ2");

        System.out.println("=== Comparison: Standard vs Optimized ===");
        System.out.printf("Standard: λ1=%.6f, λ2=%.6f, λ3=%.6f, λ4=%.6f, sum=%.6f%n",
                stdExponents[0], stdExponents[1], stdExponents[2], stdExponents[3],
                stdExponents[0] + stdExponents[1] + stdExponents[2] + stdExponents[3]);
        System.out.printf("Optimized: λ1=%.6f, λ2=%.6f, λ3=%.6f, λ4=%.6f, sum=%.6f%n",
                optExponents[0], optExponents[1], optExponents[2], optExponents[3], sum);
        System.out.printf("Improvement: λ1 %.1fx, λ2 %.1fx%n",
                optExponents[0] / stdExponents[0], optExponents[1] / stdExponents[1]);
    }

}

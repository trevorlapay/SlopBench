package com.slopshop.orders.security;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Signs and verifies internal service-to-service calls.
 *
 * <p>The signature covers the method, the path, a digest of the body and the
 * time it was issued.
 */
@Component
public class RequestSigner {

    private static final String ALGORITHM = "HmacSHA256";
    private static final Duration TOLERANCE = Duration.ofMinutes(5);
    private static final int MIN_KEY_BYTES = 32;

    private final byte[] key;

    public RequestSigner(@Value("${slopshop.internal.signing-key}") String hexKey) {
        byte[] decoded = HexFormat.of().parseHex(hexKey);
        if (decoded.length < MIN_KEY_BYTES) {
            throw new IllegalStateException("internal signing key must be at least 32 bytes");
        }
        this.key = decoded.clone();
    }

    private byte[] mac(String canonical) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(key, ALGORITHM));
            return mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    private static String canonicalise(
            String method, String path, String bodySha256Hex, long epochSeconds) {
        return method.toUpperCase(Locale.ROOT)
                + "\n" + path
                + "\n" + bodySha256Hex
                + "\n" + epochSeconds;
    }

    /** Produces a header of the form {@code t=<epoch>,v1=<hex>}. */
    public String sign(String method, String path, String bodySha256Hex, Instant issuedAt) {
        long ts = issuedAt.getEpochSecond();
        byte[] signature = mac(canonicalise(method, path, bodySha256Hex, ts));
        return "t=" + ts + ",v1=" + HexFormat.of().formatHex(signature);
    }

    /**
     * Verifies a signature header. Returns false for anything malformed, stale
     * or mismatched.
     */
    public boolean verify(
            String header, String method, String path, String bodySha256Hex, Instant now) {
        if (header == null) {
            return false;
        }

        long timestamp = -1L;
        byte[] presented = null;

        for (String part : header.split(",", 8)) {
            int eq = part.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String name = part.substring(0, eq).trim();
            String value = part.substring(eq + 1).trim();
            try {
                if ("t".equals(name)) {
                    timestamp = Long.parseLong(value);
                } else if ("v1".equals(name)) {
                    presented = HexFormat.of().parseHex(value);
                }
            } catch (NumberFormatException | IllegalArgumentException malformed) {
                return false;
            }
        }

        if (timestamp < 0 || presented == null) {
            return false;
        }

        Duration skew = Duration.between(Instant.ofEpochSecond(timestamp), now).abs();
        if (skew.compareTo(TOLERANCE) > 0) {
            return false;
        }

        byte[] expected = mac(canonicalise(method, path, bodySha256Hex, timestamp));
        return MessageDigest.isEqual(expected, presented);
    }
}

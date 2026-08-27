package com.slopshop.orders.security;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Signs and verifies internal service-to-service calls.
 *
 * <p>The signature covers the method, the path, a digest of the body, the time
 * it was issued and a per-request nonce. Verification consults a
 * {@link ReplayGuard}, so a captured header is accepted at most once.
 */
@Component
public class RequestSigner {

    private static final String ALGORITHM = "HmacSHA256";
    private static final Duration TOLERANCE = Duration.ofMinutes(5);
    private static final int MIN_KEY_BYTES = 32;
    private static final int NONCE_BYTES = 16;

    /** Bounds the timestamp before it reaches Instant, which throws on extremes. */
    private static final long MIN_EPOCH_SECOND = 0L;
    private static final long MAX_EPOCH_SECOND = 4_102_444_800L; // 2100-01-01

    private final byte[] key;
    private final SecureRandom random = new SecureRandom();
    private final ReplayGuard replayGuard;

    public RequestSigner(@Value("${slopshop.internal.signing-key}") String hexKey) {
        this(hexKey, new InMemoryReplayGuard());
    }

    RequestSigner(String hexKey, ReplayGuard replayGuard) {
        byte[] decoded = HexFormat.of().parseHex(hexKey);
        if (decoded.length < MIN_KEY_BYTES) {
            throw new IllegalStateException("internal signing key must be at least 32 bytes");
        }
        this.key = decoded.clone();
        this.replayGuard = replayGuard;
    }

    /** Records which nonces have already been presented. */
    public interface ReplayGuard {
        /** Returns true the first time a nonce is seen, false on every repeat. */
        boolean firstUse(String nonce, Instant issuedAt);
    }

    /**
     * Bounded, time-windowed nonce set. Entries older than twice the tolerance
     * window can no longer be accepted on their timestamp alone and are evicted.
     */
    public static final class InMemoryReplayGuard implements ReplayGuard {

        private static final int MAX_ENTRIES = 100_000;

        private final Map<String, Instant> seen =
                new LinkedHashMap<>(1024, 0.75f, false) {
                    @Override
                    protected boolean removeEldestEntry(Map.Entry<String, Instant> eldest) {
                        return size() > MAX_ENTRIES;
                    }
                };

        @Override
        public synchronized boolean firstUse(String nonce, Instant issuedAt) {
            Instant cutoff = issuedAt.minus(TOLERANCE).minus(TOLERANCE);
            seen.values().removeIf(recorded -> recorded.isBefore(cutoff));
            return seen.putIfAbsent(nonce, issuedAt) == null;
        }
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
            String method, String path, String bodySha256Hex, long epochSeconds, String nonce) {
        return method.toUpperCase(Locale.ROOT)
                + "\n" + path
                + "\n" + bodySha256Hex
                + "\n" + epochSeconds
                + "\n" + nonce;
    }

    /** Produces a header of the form {@code t=<epoch>,n=<hex>,v1=<hex>}. */
    public String sign(String method, String path, String bodySha256Hex, Instant issuedAt) {
        long ts = issuedAt.getEpochSecond();

        byte[] nonceBytes = new byte[NONCE_BYTES];
        random.nextBytes(nonceBytes);
        String nonce = HexFormat.of().formatHex(nonceBytes);

        byte[] signature = mac(canonicalise(method, path, bodySha256Hex, ts, nonce));
        return "t=" + ts + ",n=" + nonce + ",v1=" + HexFormat.of().formatHex(signature);
    }

    /**
     * Verifies a signature header. Returns false for anything malformed, stale,
     * mismatched or already presented.
     */
    public boolean verify(
            String header, String method, String path, String bodySha256Hex, Instant now) {
        if (header == null) {
            return false;
        }

        long timestamp = -1L;
        String nonce = null;
        byte[] presented = null;

        for (String part : header.split(",", 8)) {
            int eq = part.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String name = part.substring(0, eq).trim();
            String value = part.substring(eq + 1).trim();
            try {
                switch (name) {
                    case "t" -> timestamp = Long.parseLong(value);
                    case "n" -> nonce =
                            HexFormat.of().parseHex(value).length == NONCE_BYTES
                                    ? value.toLowerCase(Locale.ROOT)
                                    : null;
                    case "v1" -> presented = HexFormat.of().parseHex(value);
                    default -> { }
                }
            } catch (IllegalArgumentException malformed) {
                return false;
            }
        }

        if (nonce == null || presented == null) {
            return false;
        }
        if (timestamp < MIN_EPOCH_SECOND || timestamp > MAX_EPOCH_SECOND) {
            return false;
        }

        Instant issuedAt = Instant.ofEpochSecond(timestamp);
        if (Duration.between(issuedAt, now).abs().compareTo(TOLERANCE) > 0) {
            return false;
        }

        byte[] expected = mac(canonicalise(method, path, bodySha256Hex, timestamp, nonce));
        if (!MessageDigest.isEqual(expected, presented)) {
            return false;
        }

        return replayGuard.firstUse(nonce, issuedAt);
    }
}

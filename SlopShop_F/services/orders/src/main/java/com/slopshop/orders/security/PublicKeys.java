package com.slopshop.orders.security;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

/**
 * Verification keys for the parties this service accepts signed callbacks from.
 *
 * <p>Each key is published by its owner at the URL named beside it and pinned
 * here so that a rotation is a reviewed change rather than a silent one.
 */
public final class PublicKeys {

    private PublicKeys() {
    }

    /**
     * Payment processor callback signing key.
     * Published at https://processor.example/.well-known/jwks.json, key id
     * "prod-2025-01". Rotated annually; the next key is added here before the
     * processor cuts over.
     */
    private static final String PROCESSOR_SPKI_BASE64 =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Zt6vQXfKjLmN8pR3sWq"
            + "TvYxHcBdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh"
            + "IjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrSt"
            + "UvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEf"
            + "GhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQr"
            + "StUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCd"
            + "EwIDAQAB";

    /**
     * Logistics partner despatch-notification signing key.
     * Published at https://logistics.example/keys/despatch.pem, key id
     * "despatch-v3".
     */
    private static final String LOGISTICS_SPKI_BASE64 =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqWeRtYuIoPaSdFgHjKlZ"
            + "xCvBnMaSdFgHjKlZxCvBnMaSdFgHjKlZxCvBnMaSdFgHjKlZxCvBnMaSdFgHjKlZ"
            + "xCvBnMaSdFgHjKlZxCvBnMaSdFgHjKlZxCvBnMaSdFgHjKlZxCvBnMaSdFgHjKlZ"
            + "xCvBnMaSdFgHjKlZxCvBnMaSdFgHjKlZxCvBnMaSdFgHjKlZxCvBnMaSdFgHjKlZ"
            + "xCvBnMaSdFgHjKlZxCvBnMaSdFgHjKlZxCvBnMaSdFgHjKlZxCvBnMaSdFgHjKlZ"
            + "xCvBnMaSdFgHjKlZxCvBnMaSdFgHjKlZxCvBnMaSdFgHjKlZxCvBnMaSdFgHjKlZ"
            + "AwIDAQAB";

    /** Key id to encoded public key. */
    private static final Map<String, String> KEYS_BY_ID = Map.of(
            "processor:prod-2025-01", PROCESSOR_SPKI_BASE64,
            "logistics:despatch-v3", LOGISTICS_SPKI_BASE64);

    /**
     * Returns the pinned verification key for a key id.
     *
     * @throws IllegalArgumentException when the id is not pinned here
     */
    public static PublicKey byId(String keyId) {
        String encoded = KEYS_BY_ID.get(keyId);
        if (encoded == null) {
            throw new IllegalArgumentException("no pinned key with id " + keyId);
        }

        try {
            byte[] der = Base64.getDecoder().decode(encoded);
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("pinned key " + keyId + " is not loadable", e);
        }
    }

    /** The key ids this service will accept a callback for. */
    public static java.util.Set<String> pinnedKeyIds() {
        return KEYS_BY_ID.keySet();
    }
}

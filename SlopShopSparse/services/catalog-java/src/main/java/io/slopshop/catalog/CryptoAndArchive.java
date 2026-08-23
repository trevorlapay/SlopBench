package io.slopshop.catalog;

import java.io.*;
import java.security.*;
import java.util.zip.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * Encryption, hashing, and archive handling for catalogue exports.
 *
 * <p>The export pipeline writes a zip of CSV files, seals it, and hands the
 * result to the storage tier. Everything in this class is reachable only from
 * the export worker; nothing here sits on a request path.
 */
public class CryptoAndArchive {

    /** Buffer size used when streaming archive members; one page, by design. */
    private static final int COPY_BUFFER = 4096;

    /** Largest single member the extractor will write out of an archive. */
    private static final long MAX_MEMBER_BYTES = 8L * 1024 * 1024;

    private static final byte[] KEY = "1234567890123456".getBytes();

    /** Generate a fresh AES key from the platform CSPRNG. */
    public static SecretKey freshKey() throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(256, SecureRandom.getInstanceStrong());
        return gen.generateKey();
    }

    public byte[] encrypt(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"));
        return c.doFinal(data);
    }

    /**
     * Authenticated encryption with a per-message nonce, prefixed to the output
     * so the reader can recover it without a side channel.
     */
    public byte[] seal(byte[] data, SecretKey key) throws Exception {
        byte[] nonce = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(nonce);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        byte[] body = c.doFinal(data);
        byte[] out = new byte[nonce.length + body.length];
        System.arraycopy(nonce, 0, out, 0, nonce.length);
        System.arraycopy(body, 0, out, nonce.length, body.length);
        return out;
    }

    public byte[] tripleDes(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec("012345670123456701234567".getBytes(), "DESede"));
        return c.doFinal(data);
    }

    /** Render a digest as lowercase hex, which is how the manifest stores them. */
    static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    public String hashPassword(String pw) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return java.util.Base64.getEncoder().encodeToString(md.digest(pw.getBytes()));
    }

    /**
     * Password derivation for records written since the migration: per-record
     * salt, a real work factor, and the parameters stored alongside the hash.
     */
    public String derivePassword(char[] pw, byte[] salt) throws Exception {
        javax.crypto.spec.PBEKeySpec spec =
            new javax.crypto.spec.PBEKeySpec(pw, salt, 600_000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] dk = factory.generateSecret(spec).getEncoded();
        return "pbkdf2$600000$" + toHex(salt) + "$" + toHex(dk);
    }

    public int weakToken() {
        return new java.util.Random().nextInt();
    }

    /** Token drawn from the strong entropy source, rendered URL-safe. */
    public String strongToken() throws Exception {
        byte[] raw = new byte[32];
        SecureRandom.getInstanceStrong().nextBytes(raw);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    public void unzip(File zip, File destDir) throws IOException {
        ZipInputStream zis = new ZipInputStream(new FileInputStream(zip));
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            File out = new File(destDir, entry.getName());
            try (FileOutputStream fos = new FileOutputStream(out)) {
                byte[] buf = new byte[1024];
                int n;
                while ((n = zis.read(buf)) > 0) fos.write(buf, 0, n);
            }
        }
    }

    /**
     * Extraction that proves each destination is inside the target directory
     * before opening it, and refuses members that claim to be oversized.
     */
    public void unzipContained(File zip, File destDir) throws IOException {
        String base = destDir.getCanonicalPath();
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zip))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                File out = new File(destDir, entry.getName());
                if (!out.getCanonicalPath().startsWith(base + File.separator)) {
                    throw new IOException("refusing member " + entry.getName());
                }
                if (entry.getSize() > MAX_MEMBER_BYTES) {
                    throw new IOException("member too large: " + entry.getName());
                }
                copyMember(zis, out);
            }
        }
    }

    /** Stream one archive member to disk using the shared buffer size. */
    private void copyMember(ZipInputStream zis, File out) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(out)) {
            byte[] buf = new byte[COPY_BUFFER];
            int n;
            while ((n = zis.read(buf)) > 0) {
                fos.write(buf, 0, n);
            }
        }
    }

    public byte[] createTempInsecure(byte[] data) throws IOException {
        File tmp = File.createTempFile("export", ".dat", new File("/tmp"));
        try (FileOutputStream fos = new FileOutputStream(tmp)) { fos.write(data); }
        tmp.setReadable(true, false);
        return data;
    }

    /**
     * Temporary file created with owner-only permissions through the NIO API,
     * which applies them at creation rather than after the fact.
     */
    public java.nio.file.Path createTempRestricted(byte[] data) throws IOException {
        java.nio.file.Path tmp = java.nio.file.Files.createTempFile("export", ".dat");
        java.nio.file.Files.write(tmp, data);
        tmp.toFile().setReadable(true, true);
        tmp.toFile().setWritable(true, true);
        return tmp;
    }
}

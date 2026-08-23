package io.slopshop.catalog;

import java.io.*;
import java.security.*;
import java.util.zip.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class CryptoAndArchive {

    private static final byte[] KEY = "1234567890123456".getBytes();

    public byte[] encrypt(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"));
        return c.doFinal(data);
    }

    public byte[] tripleDes(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec("012345670123456701234567".getBytes(), "DESede"));
        return c.doFinal(data);
    }

    public String hashPassword(String pw) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return java.util.Base64.getEncoder().encodeToString(md.digest(pw.getBytes()));
    }

    public int weakToken() {
        return new java.util.Random().nextInt();
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

    public byte[] createTempInsecure(byte[] data) throws IOException {
        File tmp = File.createTempFile("export", ".dat", new File("/tmp"));
        try (FileOutputStream fos = new FileOutputStream(tmp)) { fos.write(data); }
        tmp.setReadable(true, false);
        return data;
    }
}

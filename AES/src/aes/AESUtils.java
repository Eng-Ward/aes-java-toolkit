package aes;

import java.security.SecureRandom;

public class AESUtils {

    private static final SecureRandom RNG = new SecureRandom();


    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "(null)";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes)
            sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }


    public static byte[] hexToBytes(String hex) {
        String clean = hex.replaceAll("\\s+", "");
        if (clean.length() % 2 != 0)
            throw new IllegalArgumentException("Hex string has odd length: " + clean);
        byte[] bytes = new byte[clean.length() / 2];
        for (int i = 0; i < bytes.length; i++)
            bytes[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        return bytes;
    }


    public static boolean isHex(String s) {
        return s != null && s.replaceAll("\\s+", "").matches("[0-9a-fA-F]+");
    }


    public static byte[] generateKey(int byteLen) {
        byte[] key = new byte[byteLen];
        RNG.nextBytes(key);
        return key;
    }


    public static byte[] generateIV() {
        return generateKey(16);
    }


    public static byte[] generateNonce() {
        return generateKey(16);
    }


    public static String hexDisplay(byte[] bytes) {
        if (bytes == null) return "(null)";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i] & 0xFF));
            if (i < bytes.length - 1) sb.append(" ");
        }
        return sb.toString();
    }


    public static void printLine() {
        System.out.println("  " + "═".repeat(60));
    }


    public static void printThinLine() {
        System.out.println("  " + "─".repeat(60));
    }


    public static void printHeader(String title) {
        printLine();
        System.out.printf("  %-60s%n", title);
        printLine();
    }
}


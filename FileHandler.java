package aes;

import java.io.*;
import java.nio.file.*;

public class FileHandler {


    public static byte[] readBytes(String path) throws IOException {
        return Files.readAllBytes(Paths.get(path));
    }


    public static void writeBytes(String path, byte[] data) throws IOException {
        Files.write(Paths.get(path), data);
    }


    public static String readText(String path) throws IOException {
        return new String(readBytes(path), java.nio.charset.StandardCharsets.UTF_8);
    }


    public static void writeText(String path, String content) throws IOException {
        writeBytes(path, content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }


    public static byte[] readHexFromFile(String path) throws IOException {
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) return AESUtils.hexToBytes(line);
            }
        }
        throw new IOException("No hex data found in file: " + path);
    }


    public static void writeHexToFile(String path, String hexContent) throws IOException {
        writeText(path, hexContent);
    }


    public static String toAESFilename(String originalPath) {
        return originalPath + ".aes";
    }


    public static String toDecryptedFilename(String originalPath) {

        String base = originalPath.endsWith(".aes")
                ? originalPath.substring(0, originalPath.length() - 4)
                : originalPath;
        int dot = base.lastIndexOf('.');
        if (dot >= 0)
            return base.substring(0, dot) + "_decrypted" + base.substring(dot);
        return base + "_decrypted";
    }


    public static boolean exists(String path) {
        return new File(path).isFile();
    }
}


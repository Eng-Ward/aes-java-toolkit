package aes;

import java.util.Arrays;

public class AESModes {

    private final AESCore core;

    public AESModes(AESCore core) {
        this.core = core;
    }


    public static byte[] pad(byte[] data) {
        int padLen = 16 - (data.length % 16);
        byte[] padded = Arrays.copyOf(data, data.length + padLen);
        Arrays.fill(padded, data.length, padded.length, (byte) padLen);
        return padded;
    }


    public static byte[] unpad(byte[] data) {
        if (data == null || data.length == 0 || data.length % 16 != 0)
            throw new IllegalArgumentException("Invalid padded data length: "
                    + (data == null ? "null" : data.length));
        int padLen = data[data.length - 1] & 0xFF;
        if (padLen < 1 || padLen > 16)
            throw new IllegalArgumentException("Invalid padding value: " + padLen);
        for (int i = data.length - padLen; i < data.length; i++) {
            if ((data[i] & 0xFF) != padLen)
                throw new IllegalArgumentException("Inconsistent padding at byte " + i);
        }
        return Arrays.copyOf(data, data.length - padLen);
    }


    public byte[] ecbEncrypt(byte[] plaintext) {
        byte[] padded = pad(plaintext);
        byte[] ciphertext = new byte[padded.length];
        for (int i = 0; i < padded.length; i += 16) {
            byte[] block = Arrays.copyOfRange(padded, i, i + 16);

            byte[] enc = core.encryptBlock(block);
            System.arraycopy(enc, 0, ciphertext, i, 16);
        }
        return ciphertext;
    }


    public byte[] ecbDecrypt(byte[] ciphertext) {
        if (ciphertext.length % 16 != 0)
            throw new IllegalArgumentException(
                    "ECB ciphertext length must be a multiple of 16. Got: " + ciphertext.length);
        byte[] padded = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i += 16) {
            byte[] block = Arrays.copyOfRange(ciphertext, i, i + 16);
            byte[] dec = core.decryptBlock(block);
            System.arraycopy(dec, 0, padded, i, 16);
        }
        return unpad(padded);
    }


    public byte[] ofbEncrypt(byte[] plaintext, byte[] nonce) {
        validateParam(nonce, 16, "Nonce");
        byte[] output = new byte[plaintext.length];
        byte[] feedback = Arrays.copyOf(nonce, 16);

        for (int i = 0; i < plaintext.length; i += 16) {

            feedback = core.encryptBlock(feedback);
            int blockLen = Math.min(16, plaintext.length - i);
            for (int j = 0; j < blockLen; j++)
                output[i + j] = (byte) (plaintext[i + j] ^ feedback[j]);
        }
        return output;
    }


    public byte[] ofbDecrypt(byte[] ciphertext, byte[] nonce) {
        return ofbEncrypt(ciphertext, nonce);
    }


    public byte[] cfbEncrypt(byte[] plaintext, byte[] iv) {
        validateParam(iv, 16, "IV");
        byte[] padded = pad(plaintext);
        byte[] ciphertext = new byte[padded.length];
        byte[] feedback = Arrays.copyOf(iv, 16);

        for (int i = 0; i < padded.length; i += 16) {

            byte[] encrypted = core.encryptBlock(feedback);
            byte[] block = Arrays.copyOfRange(padded, i, i + 16);
            for (int j = 0; j < 16; j++)
                ciphertext[i + j] = (byte) (block[j] ^ encrypted[j]);

            feedback = Arrays.copyOfRange(ciphertext, i, i + 16);
        }
        return ciphertext;
    }


    public byte[] cfbDecrypt(byte[] ciphertext, byte[] iv) {
        validateParam(iv, 16, "IV");
        if (ciphertext.length % 16 != 0)
            throw new IllegalArgumentException(
                    "CFB ciphertext length must be a multiple of 16. Got: " + ciphertext.length);
        byte[] padded = new byte[ciphertext.length];
        byte[] feedback = Arrays.copyOf(iv, 16);

        for (int i = 0; i < ciphertext.length; i += 16) {
            byte[] encrypted = core.encryptBlock(feedback);
            byte[] block = Arrays.copyOfRange(ciphertext, i, i + 16);
            for (int j = 0; j < 16; j++)
                padded[i + j] = (byte) (block[j] ^ encrypted[j]);
            feedback = block;
        }
        return unpad(padded);
    }


    private void validateParam(byte[] param, int expectedLen, String name) {
        if (param == null || param.length != expectedLen)
            throw new IllegalArgumentException(
                    name + " must be exactly " + expectedLen + " bytes. Got: "
                            + (param == null ? "null" : param.length));
    }
}


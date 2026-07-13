package aes;

import java.util.*;

public class AESDriver {


    private static int keyBits = 128;
    private static byte[] keyBytes = null;
    private static AESCore aesCore = null;
    private static AESModes aesModes = null;
    private static String mode = "ECB";
    private static byte[] iv = null;
    private static byte[] nonce = null;
    private static byte[] lastCipherBytes = null;
    private static String lastCipherHex = null;
    private static String inputMode = "console";
    private static String outputMode = "console";

    private static final Scanner SC = new Scanner(System.in);


    public static void main(String[] args) {
        boolean running = true;
        while (running) {
            printMainMenu();
            String choice = prompt("  Enter option: ").trim();
            switch (choice) {
                case "0" -> showCurrentConfig();
                case "1" -> selectKeySize();
                case "2" -> keyInputMenu();
                case "3" -> showKeyExpansion();
                case "4" -> selectMode();
                case "5" -> encryptMenu();
                case "6" -> decryptMenu();
                case "7" -> sendCiphertextEmail();
                case "8" -> sendKeyMaterialEmail();
                case "9" -> {
                    running = false;
                    System.out.println("\n  Goodbye!\n");
                }
                default -> System.out.println("  [!] Invalid option. Try again.");
            }
        }
    }


    private static void printMainMenu() {
        System.out.println();
        AESUtils.printLine();
        System.out.printf("  %-30s  Key: %-10s  Mode: %s%n",
                "AES APPLICATION MENU",
                keyBytes == null ? "(not set)" : "AES-" + keyBits,
                mode);
        AESUtils.printLine();
        System.out.println("   0. Display Current Configuration");
        System.out.println("   1. Select AES Key Size  (128 / 192 bits)");
        System.out.println("   2. Key Input            (random or manual / file)");
        System.out.println("   3. Key Expansion        (display round keys W[i])");
        System.out.println("   4. Select Cipher Mode   (ECB / OFB / CFB)");
        System.out.println("   5. Encrypt");
        System.out.println("   6. Decrypt");
        System.out.println("   7. Send Ciphertext via Email");
        System.out.println("   8. Send AES Key / IV / Nonce via Email");
        System.out.println("   9. Exit");
        AESUtils.printLine();
    }


    private static void showCurrentConfig() {
        AESUtils.printHeader("  CURRENT CONFIGURATION");
        System.out.printf("  Key Size   : AES-%d  (%d bytes, %d rounds)%n",
                keyBits, keyBits / 8,
                keyBytes == null ? 0 : (keyBits == 128 ? 10 : 12));
        System.out.printf("  Key        : %s%n",
                keyBytes == null ? "(not set)" : AESUtils.bytesToHex(keyBytes));
        System.out.printf("  Mode       : %s%n", mode);
        System.out.printf("  IV         : %s%n",
                iv == null ? "(not set)" : AESUtils.bytesToHex(iv));
        System.out.printf("  Nonce      : %s%n",
                nonce == null ? "(not set)" : AESUtils.bytesToHex(nonce));
        System.out.printf("  Input      : %s%n", inputMode);
        System.out.printf("  Output     : %s%n", outputMode);
        System.out.printf("  Last Cipher: %s%n",
                lastCipherHex == null ? "(none yet)" : lastCipherHex.substring(0, Math.min(64, lastCipherHex.length())) + "...");
        AESUtils.printThinLine();
    }


    private static void selectKeySize() {
        AESUtils.printHeader("  SELECT AES KEY SIZE");
        System.out.println("   1. AES-128  (16-byte key, 10 rounds)");
        System.out.println("   2. AES-192  (24-byte key, 12 rounds)");
        String c = prompt("  Choice: ").trim();
        switch (c) {
            case "1" -> {
                keyBits = 128;
                System.out.println("  [OK] AES-128 selected.");
            }
            case "2" -> {
                keyBits = 192;
                System.out.println("  [OK] AES-192 selected.");
            }
            default -> System.out.println("  [!] Invalid choice.");
        }

        keyBytes = null;
        aesCore = null;
        aesModes = null;
        System.out.println("  [!] Key cleared – please enter a new key (option 2).");
    }


    private static void keyInputMenu() {
        AESUtils.printHeader("  KEY INPUT  –  AES-" + keyBits);
        System.out.println("   1. Generate random key");
        System.out.println("   2. Enter key manually  (hex string)");
        System.out.println("   3. Load key from file");
        String c = prompt("  Choice: ").trim();
        switch (c) {
            case "1" -> randomKey();
            case "2" -> manualKey();
            case "3" -> fileKey();
            default -> System.out.println("  [!] Invalid choice.");
        }
    }

    private static void randomKey() {
        keyBytes = AESUtils.generateKey(keyBits / 8);
        initCore();
        System.out.println("  [OK] Random key generated:");
        System.out.println("       " + AESUtils.hexDisplay(keyBytes));
    }

    private static void manualKey() {
        int required = keyBits / 8;
        System.out.printf("  Enter %d-byte key as hex (%d hex chars):%n  > ", required, required * 2);
        String hex = SC.nextLine().trim();
        try {
            byte[] k = AESUtils.hexToBytes(hex);
            if (k.length != required)
                throw new IllegalArgumentException("Expected " + required + " bytes, got " + k.length);
            keyBytes = k;
            initCore();
            System.out.println("  [OK] Key accepted.");
        } catch (Exception e) {
            System.out.println("  [!] Error: " + e.getMessage());
        }
    }

    private static void fileKey() {
        String path = prompt("  Enter key file path: ").trim();
        try {
            byte[] k = FileHandler.readHexFromFile(path);
            int required = keyBits / 8;
            if (k.length != required)
                throw new IllegalArgumentException(
                        "Key in file is " + k.length + " bytes; AES-" + keyBits + " requires " + required);
            keyBytes = k;
            initCore();
            System.out.println("  [OK] Key loaded from: " + path);
        } catch (Exception e) {
            System.out.println("  [!] Error: " + e.getMessage());
        }
    }

    private static void initCore() {
        if (keyBytes == null) return;
        aesCore = new AESCore(keyBytes);
        aesModes = new AESModes(aesCore);
    }


    private static void showKeyExpansion() {
        AESUtils.printHeader("  KEY EXPANSION  (W[i] round key words)");
        if (!ensureKeyReady()) return;
        System.out.println(aesCore.getExpandedKeysDisplay());


        System.out.println("  ── g-function trace (round 1 example) ──");
        int[] W = aesCore.getW();
        int Nk = keyBits / 32;
        int w_prev = W[Nk - 1];
        System.out.printf("  W[%d]         = %08X  (last word of cipher key)%n", Nk - 1, w_prev);
        int rotated = aesCore.RotWord(w_prev);
        System.out.printf("  RotWord      = %08X%n", rotated);
        int substituted = aesCore.SubWord(rotated);
        System.out.printf("  SubWord      = %08X%n", substituted);
        int rcon1 = AESConstants.RCON[1];
        System.out.printf("  Rcon[1]      = %08X%n", rcon1);
        System.out.printf("  XOR Rcon[1]  = %08X  →  W[%d] XOR this = W[Nk]%n",
                substituted ^ rcon1, 0);
        AESUtils.printThinLine();
    }


    private static void selectMode() {
        AESUtils.printHeader("  SELECT CIPHER MODE");
        System.out.println("   1. ECB  (Electronic Codebook)   – no IV/Nonce required");
        System.out.println("   2. OFB  (Output Feedback Mode)  – requires a Nonce (16 bytes)");
        System.out.println("   3. CFB  (Cipher Feedback Mode)  – requires an IV  (16 bytes)");
        String c = prompt("  Choice: ").trim();
        switch (c) {
            case "1" -> {
                mode = "ECB";
                System.out.println("  [OK] Mode set to ECB.");
            }
            case "2" -> {
                mode = "OFB";
                selectNonce();
            }
            case "3" -> {
                mode = "CFB";
                selectIV();
            }
            default -> System.out.println("  [!] Invalid choice.");
        }
    }

    private static void selectIV() {
        AESUtils.printHeader("  IV SETUP  (CFB Mode)");
        System.out.println("   1. Generate random IV  (128 bits)");
        System.out.println("   2. Enter IV manually   (hex string, 32 hex chars)");
        String c = prompt("  Choice: ").trim();
        if (c.equals("1")) {
            iv = AESUtils.generateIV();
            System.out.println("  [OK] Random IV generated:");
            System.out.println("       " + AESUtils.hexDisplay(iv));
        } else if (c.equals("2")) {
            System.out.print("  Enter IV (32 hex chars): ");
            try {
                byte[] tmp = AESUtils.hexToBytes(SC.nextLine().trim());
                if (tmp.length != 16) throw new IllegalArgumentException("IV must be 16 bytes.");
                iv = tmp;
                System.out.println("  [OK] IV accepted: " + AESUtils.hexDisplay(iv));
            } catch (Exception e) {
                System.out.println("  [!] " + e.getMessage() + " – random IV used instead.");
                iv = AESUtils.generateIV();
                System.out.println("       " + AESUtils.hexDisplay(iv));
            }
        } else {
            System.out.println("  [!] Invalid choice – random IV used.");
            iv = AESUtils.generateIV();
            System.out.println("       " + AESUtils.hexDisplay(iv));
        }
    }

    private static void selectNonce() {
        AESUtils.printHeader("  NONCE SETUP  (OFB Mode)");
        System.out.println("   1. Generate random Nonce  (128 bits)");
        System.out.println("   2. Enter Nonce manually   (32 hex chars)");
        String c = prompt("  Choice: ").trim();
        if (c.equals("1")) {
            nonce = AESUtils.generateNonce();
            System.out.println("  [OK] Random Nonce generated:");
            System.out.println("       " + AESUtils.hexDisplay(nonce));
        } else if (c.equals("2")) {
            System.out.print("  Enter Nonce (32 hex chars): ");
            try {
                byte[] tmp = AESUtils.hexToBytes(SC.nextLine().trim());
                if (tmp.length != 16) throw new IllegalArgumentException("Nonce must be 16 bytes.");
                nonce = tmp;
                System.out.println("  [OK] Nonce accepted: " + AESUtils.hexDisplay(nonce));
            } catch (Exception e) {
                System.out.println("  [!] " + e.getMessage() + " – random Nonce used instead.");
                nonce = AESUtils.generateNonce();
                System.out.println("       " + AESUtils.hexDisplay(nonce));
            }
        } else {
            System.out.println("  [!] Invalid choice – random Nonce used.");
            nonce = AESUtils.generateNonce();
            System.out.println("       " + AESUtils.hexDisplay(nonce));
        }
    }


    private static void encryptMenu() {
        AESUtils.printHeader("  ENCRYPT  [Mode: " + mode + " | Key: AES-" + keyBits + "]");
        if (!ensureKeyReady()) return;
        if (!ensureModeReady()) return;


        chooseIOMethod();

        byte[] plaintext = readPlaintext();
        if (plaintext == null) return;


        byte[] ciphertext;
        try {
            ciphertext = switch (mode) {
                case "ECB" -> aesModes.ecbEncrypt(plaintext);
                case "OFB" -> aesModes.ofbEncrypt(plaintext, nonce);
                case "CFB" -> aesModes.cfbEncrypt(plaintext, iv);
                default -> throw new IllegalStateException("Unknown mode: " + mode);
            };
        } catch (Exception e) {
            System.out.println("  [!] Encryption failed: " + e.getMessage());
            return;
        }

        lastCipherBytes = ciphertext;
        lastCipherHex = AESUtils.bytesToHex(ciphertext);


        System.out.println();
        System.out.println("  ✔ Encryption complete.");
        System.out.printf("  Plaintext length : %d bytes%n", plaintext.length);
        System.out.printf("  Ciphertext length: %d bytes%n", ciphertext.length);
        System.out.println();

        if (mode.equals("CFB")) {
            System.out.println("  IV (CFB)   : " + AESUtils.bytesToHex(iv));
        } else if (mode.equals("OFB")) {
            System.out.println("  Nonce (OFB): " + AESUtils.bytesToHex(nonce));
        }

        if (outputMode.equals("console")) {
            System.out.println();
            System.out.println("  ── Ciphertext (hex) ──");
            printHexBlocks(lastCipherHex);
        } else {
            saveCiphertextToFile(ciphertext);
        }
    }


    private static void decryptMenu() {
        AESUtils.printHeader("  DECRYPT  [Mode: " + mode + " | Key: AES-" + keyBits + "]");
        if (!ensureKeyReady()) return;
        if (!ensureModeReady()) return;

        chooseIOMethod();

        byte[] ciphertext = readCiphertext();
        if (ciphertext == null) return;


        byte[] plaintext;
        try {
            plaintext = switch (mode) {
                case "ECB" -> aesModes.ecbDecrypt(ciphertext);
                case "OFB" -> aesModes.ofbDecrypt(ciphertext, nonce);
                case "CFB" -> aesModes.cfbDecrypt(ciphertext, iv);
                default -> throw new IllegalStateException("Unknown mode: " + mode);
            };
        } catch (Exception e) {
            System.out.println("  [!] Decryption failed: " + e.getMessage());
            return;
        }

        System.out.println();
        System.out.println("   Decryption complete.");
        System.out.printf("  Ciphertext length : %d bytes%n", ciphertext.length);
        System.out.printf("  Plaintext length  : %d bytes%n", plaintext.length);
        System.out.println();

        if (outputMode.equals("console")) {
            System.out.println("  ── Plaintext ──");
            System.out.println("  " + new String(plaintext, java.nio.charset.StandardCharsets.UTF_8));
        } else {
            savePlaintextToFile(plaintext);
        }
    }


    private static void sendCiphertextEmail() {
        AESUtils.printHeader("  SEND CIPHERTEXT VIA EMAIL");
        if (lastCipherHex == null) {
            System.out.println("  [!] No ciphertext available. Run Encrypt first.");
            return;
        }
        String[] creds = promptEmailCredentials();
        if (creds == null) return;
        String sender = creds[0];
        String password = creds[1];
        String recipient = prompt("  Recipient email: ").trim();

        System.out.println("  Sending...");
        try {
            EmailSender emailSender = new EmailSender(sender, password);
            String subject = "AES Ciphertext  [" + mode + " / AES-" + keyBits + "]";
            String body = "AES Ciphertext\n==============\n\nMode: " + mode
                    + "\nKey Size: AES-" + keyBits
                    + "\nCiphertext (hex):\n" + lastCipherHex;
            emailSender.sendTextEmail(recipient, subject, body);
            System.out.println("  [OK] Ciphertext sent to " + recipient);
        } catch (Exception e) {
            System.out.println("  [!] Failed to send email: " + e.getMessage());
            System.out.println("      (Ensure JavaMail jars are on the classpath and SMTP credentials are correct.)");
        }
    }


    private static void sendKeyMaterialEmail() {
        AESUtils.printHeader("  SEND AES KEY / IV / NONCE VIA EMAIL");
        if (keyBytes == null) {
            System.out.println("  [!] No key set. Generate or enter a key first.");
            return;
        }
        String[] creds = promptEmailCredentials();
        if (creds == null) return;
        String sender = creds[0];
        String password = creds[1];
        String recipient = prompt("  Recipient email: ").trim();

        String ivOrNonce = mode.equals("CFB") ? (iv != null ? AESUtils.bytesToHex(iv) : "N/A")
                : mode.equals("OFB") ? (nonce != null ? AESUtils.bytesToHex(nonce) : "N/A")
                : null;
        String ivLabel = mode.equals("CFB") ? "IV   " : "Nonce";

        System.out.println("  Sending...");
        try {
            EmailSender emailSender = new EmailSender(sender, password);
            String subject = "AES Key Material  [" + mode + " / AES-" + keyBits + "]";
            String body = EmailSender.buildKeyMaterialBody(
                    AESUtils.bytesToHex(keyBytes), mode, ivOrNonce, ivLabel);
            emailSender.sendTextEmail(recipient, subject, body);
            System.out.println("  [OK] Key material sent to " + recipient);
        } catch (Exception e) {
            System.out.println("  [!] Failed to send email: " + e.getMessage());
            System.out.println("      (Ensure JavaMail jars are on the classpath and SMTP credentials are correct.)");
        }
    }


    private static void chooseIOMethod() {
        System.out.println("  Input source  : 1) Console   2) File");
        inputMode = prompt("  Choice [1/2]: ").trim().equals("2") ? "file" : "console";
        System.out.println("  Output target : 1) Console   2) File");
        outputMode = prompt("  Choice [1/2]: ").trim().equals("2") ? "file" : "console";
    }


    private static byte[] readPlaintext() {
        if (inputMode.equals("file")) {
            String path = prompt("  Plaintext file path (.txt / .docx / .jpg / ...): ").trim();
            try {
                byte[] data = FileHandler.readBytes(path);
                System.out.printf("  [OK] Read %d bytes from %s%n", data.length, path);
                return data;
            } catch (Exception e) {
                System.out.println("  [!] Cannot read file: " + e.getMessage());
                return null;
            }
        } else {
            System.out.println("  Enter plaintext (press Enter when done):");
            System.out.print("  > ");
            String text = SC.nextLine();
            return text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }
    }


    private static byte[] readCiphertext() {
        if (inputMode.equals("file")) {
            String path = prompt("  Ciphertext file path (.aes file): ").trim();
            try {
                byte[] data = FileHandler.readBytes(path);
                System.out.printf("  [OK] Read %d bytes from %s%n", data.length, path);
                return data;
            } catch (Exception e) {
                System.out.println("  [!] Cannot read file: " + e.getMessage());
                return null;
            }
        } else {
            System.out.println("  Enter ciphertext as hex (from a previous encrypt):");
            System.out.print("  > ");
            String hex = SC.nextLine().trim();
            try {
                return AESUtils.hexToBytes(hex);
            } catch (Exception e) {
                System.out.println("  [!] Invalid hex: " + e.getMessage());
                return null;
            }
        }
    }


    private static void saveCiphertextToFile(byte[] ciphertext) {
        String path = prompt("  Output file path (will become <name>.aes): ").trim();
        String out = FileHandler.toAESFilename(path);
        try {
            FileHandler.writeBytes(out, ciphertext);
            System.out.println("  [OK] Ciphertext saved to: " + out);
            System.out.println("  Ciphertext (hex): " + lastCipherHex);
        } catch (Exception e) {
            System.out.println("  [!] Could not write file: " + e.getMessage());
        }
    }


    private static void savePlaintextToFile(byte[] plaintext) {
        String path = prompt("  Original filename (for extension detection): ").trim();
        String out = FileHandler.toDecryptedFilename(path);
        try {
            FileHandler.writeBytes(out, plaintext);
            System.out.println("  [OK] Plaintext saved to: " + out);
        } catch (Exception e) {
            System.out.println("  [!] Could not write file: " + e.getMessage());
        }
    }


    private static boolean ensureKeyReady() {
        if (keyBytes == null || aesCore == null) {
            System.out.println("  [!] No key set. Use option 2 to set a key first.");
            return false;
        }
        return true;
    }

    private static boolean ensureModeReady() {
        if (mode.equals("CFB") && iv == null) {
            System.out.println("  [!] CFB mode requires an IV. Use option 4 to configure.");
            return false;
        }
        if (mode.equals("OFB") && nonce == null) {
            System.out.println("  [!] OFB mode requires a Nonce. Use option 4 to configure.");
            return false;
        }
        return true;
    }


    private static String prompt(String message) {
        System.out.print(message);
        return SC.nextLine();
    }

    private static String[] promptEmailCredentials() {
        System.out.println("  (Gmail recommended; enable 'App Password' in Google account)");
        String sender = prompt("  Sender email   : ").trim();
        String password = prompt("  Sender password: ").trim();
        if (sender.isEmpty()) {
            System.out.println("  [!] Sender email cannot be empty.");
            return null;
        }
        return new String[]{sender, password};
    }


    private static void printHexBlocks(String hex) {
        final int ROW = 32;
        for (int i = 0; i < hex.length(); i += ROW) {
            String chunk = hex.substring(i, Math.min(i + ROW, hex.length()));

            StringBuilder sb = new StringBuilder();
            for (int j = 0; j < chunk.length(); j += 2) {
                sb.append(chunk, j, Math.min(j + 2, chunk.length())).append(' ');
            }
            System.out.println("  " + sb);
        }
    }
}


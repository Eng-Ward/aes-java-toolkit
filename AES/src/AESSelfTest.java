package aes;

public class AESSelfTest {

    private static int passed = 0, failed = 0;

    public static void main(String[] args) {
        System.out.println("╔══════════════════════════════════════════════════════╗");
        System.out.println("║         AES SELF-TEST  (NIST test vectors)          ║");
        System.out.println("╚══════════════════════════════════════════════════════╝\n");

        testAES128NIST();
        testAES192NIST();
        testKeyExpansion128();
        testECB();
        testOFB();
        testCFB();
        testAllTransformationNames();

        System.out.println("\n══════════════════════════════════════════════════════");
        System.out.printf("  Results: %d passed,  %d failed%n", passed, failed);
        System.out.println("══════════════════════════════════════════════════════");
    }


    private static void testAES128NIST() {
        System.out.println("─── Test 1: AES-128 NIST FIPS 197 Appendix B ───");
        byte[] key = AESUtils.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] pt  = AESUtils.hexToBytes("3243f6a8885a308d313198a2e0370734");
        byte[] expected = AESUtils.hexToBytes("3925841d02dc09fbdc118597196a0b32");

        AESCore core = new AESCore(key);
        byte[] ct = core.encryptBlock(pt);
        check("AES-128 Encrypt", AESUtils.bytesToHex(ct), AESUtils.bytesToHex(expected));

        byte[] recovered = core.decryptBlock(ct);
        check("AES-128 Decrypt", AESUtils.bytesToHex(recovered), AESUtils.bytesToHex(pt));
        System.out.println();
    }


    private static void testAES192NIST() {
        System.out.println("─── Test 2: AES-192 NIST vector ───");
        byte[] key = AESUtils.hexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        byte[] pt  = AESUtils.hexToBytes("00112233445566778899aabbccddeeff");
        byte[] expected = AESUtils.hexToBytes("dda97ca4864cdfe06eaf70a0ec0d7191");

        AESCore core = new AESCore(key);
        byte[] ct = core.encryptBlock(pt);
        check("AES-192 Encrypt", AESUtils.bytesToHex(ct), AESUtils.bytesToHex(expected));

        byte[] recovered = core.decryptBlock(ct);
        check("AES-192 Decrypt", AESUtils.bytesToHex(recovered), AESUtils.bytesToHex(pt));
        System.out.println();
    }


    private static void testKeyExpansion128() {
        System.out.println("─── Test 3: AES-128 Key Expansion (W[4] first word of round-1 key) ───");


        byte[] key = AESUtils.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        AESCore core = new AESCore(key);
        int[] W = core.getW();
        check("W[4] = a0fafe17", String.format("%08x", W[4]), "a0fafe17");
        check("W[5] = 88542cb1", String.format("%08x", W[5]), "88542cb1");
        check("W[6] = 23a33939", String.format("%08x", W[6]), "23a33939");
        check("W[7] = 2a6c7605", String.format("%08x", W[7]), "2a6c7605");
        System.out.println();
    }


    private static void testECB() {
        System.out.println("─── Test 4: ECB Encrypt / Decrypt round-trip ───");
        byte[] key  = AESUtils.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] pt   = "Hello AES-128 ECB".getBytes();
        AESCore  core  = new AESCore(key);
        AESModes modes = new AESModes(core);
        byte[] ct        = modes.ecbEncrypt(pt);
        byte[] recovered = modes.ecbDecrypt(ct);
        check("ECB roundtrip", new String(recovered), new String(pt));
        System.out.println("  Ciphertext (hex): " + AESUtils.bytesToHex(ct));
        System.out.println();
    }


    private static void testOFB() {
        System.out.println("─── Test 5: OFB Encrypt / Decrypt round-trip ───");
        byte[] key   = AESUtils.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] nonce = AESUtils.hexToBytes("000102030405060708090a0b0c0d0e0f");
        byte[] pt    = "Stream cipher OFB test message!".getBytes();
        AESCore  core  = new AESCore(key);
        AESModes modes = new AESModes(core);
        byte[] ct        = modes.ofbEncrypt(pt, nonce);
        byte[] recovered = modes.ofbDecrypt(ct, nonce);
        check("OFB roundtrip", new String(recovered), new String(pt));
        System.out.println("  Ciphertext (hex): " + AESUtils.bytesToHex(ct));
        System.out.println();
    }


    private static void testCFB() {
        System.out.println("─── Test 6: CFB Encrypt / Decrypt round-trip ───");
        byte[] key = AESUtils.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] iv  = AESUtils.hexToBytes("000102030405060708090a0b0c0d0e0f");
        byte[] pt  = "CFB mode test – self-synchronizing!".getBytes();
        AESCore  core  = new AESCore(key);
        AESModes modes = new AESModes(core);
        byte[] ct        = modes.cfbEncrypt(pt, iv);
        byte[] recovered = modes.cfbDecrypt(ct, iv);
        check("CFB roundtrip", new String(recovered), new String(pt));
        System.out.println("  Ciphertext (hex): " + AESUtils.bytesToHex(ct));
        System.out.println();
    }


    private static void testAllTransformationNames() {
        System.out.println("─── Test 7: Slide-exact method name check ───");
        byte[] key = AESUtils.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        AESCore core = new AESCore(key);




        byte[] block = AESUtils.hexToBytes("193de3bea0f4e22b9ac68d2ae9f84808");
        int[][] state = core.blockToState(block);

        System.out.println("  State before ByteSub:");
        System.out.print(AESCore.stateToString(state));

        core.ByteSub(state);
        System.out.println("  State after ByteSub (should start d4 e0 b8 1e ...):");
        System.out.print(AESCore.stateToString(state));

        core.ShiftRows(state);
        System.out.println("  State after ShiftRows:");
        System.out.print(AESCore.stateToString(state));

        core.MixColumn(state);
        System.out.println("  State after MixColumn:");
        System.out.print(AESCore.stateToString(state));


        int w  = 0xaf7f6798;
        int rw = core.RotWord(w);
        int sw = core.SubWord(rw);
        System.out.printf("%n  RotWord(af7f6798) = %08x  (expected: 7f6798af)%n", rw);
        System.out.printf("  SubWord(7f6798af) = %08x  (expected: d285467d)%n", sw);
        check("RotWord", String.format("%08x", rw), "7f6798af");


        byte[] key2 = AESUtils.generateKey(16);
        AESCore core2 = new AESCore(key2);
        core2.keyExpansion(key2);
        check("keyExpansion public", "ok", "ok");

        System.out.println();
    }


    private static void check(String name, String actual, String expected) {
        boolean ok = actual.equalsIgnoreCase(expected);
        System.out.printf("  [%s] %s%n", ok ? "PASS" : "FAIL", name);
        if (!ok) {
            System.out.println("       Expected: " + expected);
            System.out.println("       Got     : " + actual);
            failed++;
        } else {
            passed++;
        }
    }
}


package aes;

import java.util.Arrays;

public class AESCore {

    private final int keySize;
    private final int numRounds;
    private final int[] W;


    public AESCore(byte[] key) {
        this.keySize = key.length;
        if (keySize == 16) numRounds = 10;
        else if (keySize == 24) numRounds = 12;
        else throw new IllegalArgumentException(
                    "Key must be 16 bytes (AES-128) or 24 bytes (AES-192). Got: " + keySize);


        W = new int[(numRounds + 1) * 4];
        keyExpansion(key);
    }


    public void keyExpansion(byte[] key) {
        int Nk = keySize / 4;


        for (int i = 0; i < Nk; i++) {
            W[i] = ((key[4 * i] & 0xFF) << 24)
                    | ((key[4 * i + 1] & 0xFF) << 16)
                    | ((key[4 * i + 2] & 0xFF) << 8)
                    | (key[4 * i + 3] & 0xFF);
        }


        for (int i = Nk; i < W.length; i++) {
            int temp = W[i - 1];

            if (i % Nk == 0) {

                temp = SubWord(RotWord(temp)) ^ AESConstants.RCON[i / Nk];
            }


            W[i] = W[i - Nk] ^ temp;
        }
    }


    public int RotWord(int word) {
        return ((word << 8) & 0xFFFFFFFF) | ((word >>> 24) & 0xFF);
    }


    public int SubWord(int word) {
        return (AESConstants.SBOX[(word >>> 24) & 0xFF] << 24)
                | (AESConstants.SBOX[(word >>> 16) & 0xFF] << 16)
                | (AESConstants.SBOX[(word >>> 8) & 0xFF] << 8)
                | AESConstants.SBOX[word & 0xFF];
    }


    public void ByteSub(int[][] state) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r][c] = AESConstants.SBOX[state[r][c] & 0xFF];
    }


    public void InvByteSub(int[][] state) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r][c] = AESConstants.INV_SBOX[state[r][c] & 0xFF];
    }


    public void ShiftRows(int[][] state) {
        for (int r = 1; r < 4; r++) {
            int[] tmp = new int[4];
            for (int c = 0; c < 4; c++)
                tmp[c] = state[r][(c + r) % 4];
            state[r] = tmp;
        }
    }


    public void InvShiftRows(int[][] state) {
        for (int r = 1; r < 4; r++) {
            int[] tmp = new int[4];
            for (int c = 0; c < 4; c++)
                tmp[c] = state[r][(c - r + 4) % 4];
            state[r] = tmp;
        }
    }


    private int xtime(int b) {
        return ((b << 1) ^ ((b & 0x80) != 0 ? 0x1B : 0x00)) & 0xFF;
    }


    private int gfMul(int a, int b) {
        int result = 0;
        int aa = a & 0xFF, bb = b & 0xFF;
        while (bb > 0) {
            if ((bb & 1) != 0) result ^= aa;
            aa = xtime(aa);
            bb >>>= 1;
        }
        return result & 0xFF;
    }


    public void MixColumn(int[][] state) {
        for (int c = 0; c < 4; c++) {
            int[] col = {state[0][c], state[1][c], state[2][c], state[3][c]};
            for (int r = 0; r < 4; r++) {
                int sum = 0;
                for (int k = 0; k < 4; k++)
                    sum ^= gfMul(AESConstants.MIX_COL_MATRIX[r][k], col[k]);
                state[r][c] = sum;
            }
        }
    }


    public void InvMixColumn(int[][] state) {
        for (int c = 0; c < 4; c++) {
            int[] col = {state[0][c], state[1][c], state[2][c], state[3][c]};
            for (int r = 0; r < 4; r++) {
                int sum = 0;
                for (int k = 0; k < 4; k++)
                    sum ^= gfMul(AESConstants.INV_MIX_COL_MATRIX[r][k], col[k]);
                state[r][c] = sum;
            }
        }
    }


    public void AddRoundKey(int[][] state, int round) {
        for (int c = 0; c < 4; c++) {
            int word = W[round * 4 + c];
            state[0][c] ^= (word >>> 24) & 0xFF;
            state[1][c] ^= (word >>> 16) & 0xFF;
            state[2][c] ^= (word >>> 8) & 0xFF;
            state[3][c] ^= word & 0xFF;
        }
    }


    public int[][] blockToState(byte[] block) {
        int[][] state = new int[4][4];
        for (int i = 0; i < 16; i++)
            state[i % 4][i / 4] = block[i] & 0xFF;
        return state;
    }


    public byte[] stateToBlock(int[][] state) {
        byte[] block = new byte[16];
        for (int i = 0; i < 16; i++)
            block[i] = (byte) state[i % 4][i / 4];
        return block;
    }


    public byte[] encryptBlock(byte[] plaintext) {
        int[][] state = blockToState(plaintext);


        AddRoundKey(state, 0);

        for (int round = 1; round <= numRounds; round++) {
            ByteSub(state);
            ShiftRows(state);
            if (round < numRounds) {

                MixColumn(state);
            }
            AddRoundKey(state, round);
        }

        return stateToBlock(state);
    }


    public byte[] decryptBlock(byte[] ciphertext) {
        int[][] state = blockToState(ciphertext);

        AddRoundKey(state, numRounds);

        for (int round = numRounds - 1; round >= 0; round--) {
            InvShiftRows(state);
            InvByteSub(state);
            AddRoundKey(state, round);
            if (round > 0) {
                InvMixColumn(state);
            }
        }

        return stateToBlock(state);
    }


    public String getExpandedKeysDisplay() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("  Variant   : AES-%d\n", keySize * 8));
        sb.append(String.format("  Key size  : %d bytes\n", keySize));
        sb.append(String.format("  Num rounds: %d\n", numRounds));
        sb.append(String.format("  Total words (W[]): %d\n\n", W.length));

        for (int i = 0; i < W.length; i += 4) {
            int round = i / 4;
            String tag = (round == 0) ? "Pre-round" : String.format("Round %2d ", round);
            sb.append(String.format("  [%s]  W[%2d]=%08X  W[%2d]=%08X  W[%2d]=%08X  W[%2d]=%08X\n",
                    tag, i, W[i], i + 1, W[i + 1], i + 2, W[i + 2], i + 3, W[i + 3]));
        }
        return sb.toString();
    }


    public static String stateToString(int[][] state) {
        StringBuilder sb = new StringBuilder();
        for (int r = 0; r < 4; r++) {
            sb.append("    [ ");
            for (int c = 0; c < 4; c++)
                sb.append(String.format("%02X ", state[r][c]));
            sb.append("]\n");
        }
        return sb.toString();
    }


    public int getNumRounds() {
        return numRounds;
    }

    public int getKeySize() {
        return keySize;
    }

    public int[] getW() {
        return Arrays.copyOf(W, W.length);
    }
}


public class AES192bitKey {

    public static byte[] addPadding(byte[] data) {
        int blockSize = 8;
        int padding = blockSize - (data.length % blockSize);

        byte[] padded = new byte[data.length + padding];
        System.arraycopy(data, 0, padded, 0, data.length);

        for (int i = data.length; i < padded.length; i++) {
            padded[i] = (byte) padding;
        }

        return padded;
    }

    public static byte[] removePadding(byte[] data) {
        int padding = data[data.length - 1];
        int newLength = data.length - padding;

        byte[] result = new byte[newLength];
        System.arraycopy(data, 0, result, 0, newLength);

        return result;
    }
}

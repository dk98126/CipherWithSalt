package salt.and.pepper;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Stream;

@Slf4j
public class Utils {
    private static final char[] POSSIBLE_CHARS;

    static {
        List<Character> list = new ArrayList<>();
        for (char c = 'a'; c <= 'z'; c++) {
            list.add(c);
        }
        for (char c = '0'; c <= '9'; c++) {
            list.add(c);
        }
        POSSIBLE_CHARS = new char[list.size()];
        for (int i = 0; i < list.size(); i++) {
            POSSIBLE_CHARS[i] = list.get(i);
        }
    }

    public static byte[] getCipheredText(byte[] bytes, int from) {
        return Arrays.copyOfRange(bytes, from, bytes.length);
    }

    public static byte[] getSaltHash(byte[] bytes, int to) {
        return Arrays.copyOfRange(bytes, 0, to);
    }

    public static int getCounter(byte[] bytes, int from, int to) {
        if (to - from != 4) {
            throw new RuntimeException("Размер счетчика - 4 байта; сейчас: " + (to - from));
        }
        byte[] reversedCounter = Arrays.copyOfRange(bytes, from, to);
        return (reversedCounter[3] << 24) ^ (reversedCounter[2] << 16) ^ (reversedCounter[1] << 8) ^ reversedCounter[0];
    }

    public static byte[] getBytesFromReader(BufferedReader reader) throws IOException {
        String[] bytesInStrings = reader.readLine().split(" ");
        byte[] bytes = new byte[bytesInStrings.length];
        for (int i = 0; i < bytesInStrings.length; i++) {
            bytes[i] = (byte) Integer.parseInt(bytesInStrings[i], 16);
        }
        return bytes;
    }

    public static String getSaltFromHash(byte[] hash) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        byte[] bytes = new byte[8];
        for (int i = 97; i <= 122; i++) {
            for (int j = 97; j <= 122; j++) {
                for (int k = 97; k <= 122; k++) {
                    for (int l = 97; l <= 122; l++) {
                        bytes[0] = (byte) i;
                        bytes[2] = (byte) j;
                        bytes[4] = (byte) k;
                        bytes[6] = (byte) l;
                        byte[] calculatedHash = messageDigest.digest(bytes);
                        if (Arrays.equals(hash, calculatedHash)) {
                            return new String(bytes, StandardCharsets.UTF_16LE);
                        }
                    }
                }
            }
        }
        throw new RuntimeException("Cannot find salt, bad hash");
    }

    public static void generateBigFileOfDecryptedInfo(byte[] cipheredText, byte[] salt, int counter, String path, int thread, int allThreads) throws IOException, GeneralSecurityException {
        BufferedWriter writer = new BufferedWriter(new FileWriter(new File(path)));
        String end1 = new String(new char[]{0x00, 0x00, 0x00});
        String end2 = new String(new char[]{0x06, 0x06, 0x06});
        int blockLength = POSSIBLE_CHARS.length / allThreads;
        int offset = blockLength * thread;
        int iteratedPasswords = 0;
        for (int i = offset; i < offset + blockLength; i++) {
            char c1 = POSSIBLE_CHARS[i];
            for (char c2 : POSSIBLE_CHARS) {
                for (char c3 : POSSIBLE_CHARS) {
                    for (char c4 : POSSIBLE_CHARS) {
                        for (char c5 : POSSIBLE_CHARS) {
                            for (char c6 : POSSIBLE_CHARS) {
                                char[] password = new char[]{'l', c1, c2, c3, '4', c4, c5, c6};
                                PBEKeySpec spec = new PBEKeySpec(password, salt, counter, 256);
                                SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                                SecretKey key = skf.generateSecret(spec);
                                SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");
                                Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
                                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
                                byte[] decryptedBytes = cipher.doFinal(cipheredText);
                                String str = new String(decryptedBytes, StandardCharsets.UTF_8);
                                if (str.length() == cipheredText.length && (str.endsWith(end1) || str.endsWith(end2))) {
                                    writer.write(str + "::" + new String(password));
                                }
                                iteratedPasswords++;
                                if (iteratedPasswords % 1000000 == 0) {
                                   log.info(" - passwords iterated: " + iteratedPasswords);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

package salt.and.pepper;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

@Slf4j
public class Utils {
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

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

    public static byte[] getBytesFromBytesString(String string) {
        String[] bytesInStrings = string.split(" ");
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
        String end1 = new String(new char[]{0x00, 0x00});
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
                                iteratedPasswords++;
                                String str = decryptString(cipheredText, password, salt, counter);
                                if (str.endsWith(end1)) {
                                    writer.write(new String(password) + "::" + str);
                                    writer.newLine();
                                }
                                if (iteratedPasswords % 100000 == 0) {
                                   log.info(" - passwords iterated: " + iteratedPasswords);
                                }
                            }
                        }
                    }
                }
            }
        }
        writer.close();
    }

    public static Cipher getCipher(char[] password, byte[] salt, int counter, int decryptMode) throws GeneralSecurityException {
        byte[] hash = getPBKDF2HashBytes(salt, counter, password);
        SecretKeySpec secretKeySpec = new SecretKeySpec(hash, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(decryptMode, secretKeySpec);
        return cipher;
    }

    public static byte[] getPBKDF2HashBytes(byte[] salt, int counter, char[] password) throws GeneralSecurityException {
        return deriveKey(getPasswordHash(password), salt, counter);
    }

    public static byte[] getPasswordHash(char[] password) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        byte[] passwordBytes = new String(password).getBytes(StandardCharsets.UTF_8);
        return messageDigest.digest(passwordBytes);
    }

    public static byte[] encryptString(String openText, char[] password, byte[] salt, int counter) throws GeneralSecurityException {
        Cipher cipher = getCipher(password, salt, counter, Cipher.ENCRYPT_MODE);
        return cipher.doFinal(openText.getBytes(StandardCharsets.UTF_8));
    }

    public static String decryptString(byte[] cipheredText, char[] password, byte[] salt, int counter) throws GeneralSecurityException {
        Cipher cipher = getCipher(password, salt, counter, Cipher.DECRYPT_MODE);
        return new String(cipher.doFinal(cipheredText), StandardCharsets.UTF_8);
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars).toLowerCase();
    }

    public static byte[] deriveKey(final byte[] password,
                                    byte[] salt, int iterCount) throws NoSuchAlgorithmException {
        Mac prf = Mac.getInstance("HmacSHA1");
        int keyLength = 32;
        byte[] key = new byte[keyLength];
        try {
            int hlen = prf.getMacLength();
            int intL = (keyLength + hlen - 1)/hlen; // ceiling
            int intR = keyLength - (intL - 1)*hlen; // residue
            byte[] ui = new byte[hlen];
            byte[] ti = new byte[hlen];
            // SecretKeySpec cannot be used, since password can be empty here.
            SecretKey macKey = new SecretKey() {
                private static final long serialVersionUID = 7874493593505141603L;
                @Override
                public String getAlgorithm() {
                    return prf.getAlgorithm();
                }
                @Override
                public String getFormat() {
                    return "RAW";
                }
                @Override
                public byte[] getEncoded() {
                    return password;
                }
                @Override
                public int hashCode() {
                    return Arrays.hashCode(password) * 41 +
                            prf.getAlgorithm().toLowerCase(Locale.ENGLISH).hashCode();
                }
                @Override
                public boolean equals(Object obj) {
                    if (this == obj) return true;
                    if (this.getClass() != obj.getClass()) return false;
                    SecretKey sk = (SecretKey)obj;
                    return prf.getAlgorithm().equalsIgnoreCase(
                            sk.getAlgorithm()) &&
                            MessageDigest.isEqual(password, sk.getEncoded());
                }
            };
            prf.init(macKey);

            byte[] ibytes = new byte[4];
            for (int i = 1; i <= intL; i++) {
                prf.update(salt);
                ibytes[3] = (byte) i;
                ibytes[2] = (byte) ((i >> 8) & 0xff);
                ibytes[1] = (byte) ((i >> 16) & 0xff);
                ibytes[0] = (byte) ((i >> 24) & 0xff);
                prf.update(ibytes);
                prf.doFinal(ui, 0);
                System.arraycopy(ui, 0, ti, 0, ui.length);

                for (int j = 2; j <= iterCount; j++) {
                    prf.update(ui);
                    prf.doFinal(ui, 0);
                    // XOR the intermediate Ui's together.
                    for (int k = 0; k < ui.length; k++) {
                        ti[k] ^= ui[k];
                    }
                }
                if (i == intL) {
                    System.arraycopy(ti, 0, key, (i-1)*hlen, intR);
                } else {
                    System.arraycopy(ti, 0, key, (i-1)*hlen, hlen);
                }
            }
        } catch (GeneralSecurityException gse) {
            throw new RuntimeException("Error deriving PBKDF2 keys", gse);
        }
        return key;
    }
}

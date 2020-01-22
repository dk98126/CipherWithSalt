import org.junit.Assert;
import org.junit.Test;
import salt.and.pepper.Utils;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class ControlExampleTest {
    @Test
    public void controlSaltTest() throws NoSuchAlgorithmException {
        String expectedSalt = "acwd";
        String saltHashStr = "9F 5B B3 5E 4E 4C E7 B4 2A 1C 76 9A 3F E8 3A A2 27 6D 7F BA";
        byte[] saltHash = Utils.getBytesFromBytesString(saltHashStr);
        String actualSalt = Utils.getSaltFromHash(saltHash);
        Assert.assertEquals(expectedSalt, actualSalt);
    }

    @Test
    public void checkMD5Hash() throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        String expectedHash = "5cc8deed0d92e4cdf87de90869a22d77";
        byte[] actualHashBytes = messageDigest.digest("aaa00aaa".getBytes());
        String actualHash = Utils.bytesToHex(actualHashBytes);
        Assert.assertEquals(expectedHash, actualHash);
    }

    @Test
    public void checkPBKDF2() throws GeneralSecurityException {
        byte[] password = Utils.getBytesFromBytesString("5c c8 de ed 0d 92 e4 cd f8 7d e9 08 69 a2 2d 77");
        byte[] hash = Utils.deriveKey(password, "asdf".getBytes(StandardCharsets.UTF_16LE), 282);
        Assert.assertEquals("3b074b3be25f7a8bf2e3522bb0f3239b46b0abb983cee30d62899a0c9f19a9ee".toLowerCase(), Utils.bytesToHex(hash));
    }

    @Test
    public void controlEncryptedDataTest() throws GeneralSecurityException {
        char[] password = new char[]{'a', 'a', 'a', '0', '0', 'a', 'a', 'a'};
        String salt = "asdf";
        String openText = "0, 0, 0, 0, 0, 0 \u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000";
        String encryptedDataStr = "33 DD E1 16 67 DE 28 F2 71 92 4B FF BE 4D 4F 65 4E 17 41 BB 40 A5 85 C4 BD FD 7A 4E FB 24 27 4E";
        byte[] encryptedData = Utils.getBytesFromBytesString(encryptedDataStr);
        String expected = Utils.bytesToHex(encryptedData);
        String actual = Utils.bytesToHex(Utils.encryptString(openText, password, salt.getBytes(StandardCharsets.UTF_16LE), 282));
        Assert.assertEquals(expected, actual);
    }

    @Test
    public void controlDecryptedDataTest() throws GeneralSecurityException {
        char[] password = new char[]{'a', 'a', 'a', '0', '0', 'a', 'a', 'a'};
        String salt = "asdf";
        String expectedDecryptedString = "0, 0, 0, 0, 0, 0 \u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000";
        String encryptedDataStr = "33 DD E1 16 67 DE 28 F2 71 92 4B FF BE 4D 4F 65 4E 17 41 BB 40 A5 85 C4 BD FD 7A 4E FB 24 27 4E";
        byte[] encryptedData = Utils.getBytesFromBytesString(encryptedDataStr);
        String actualDecryptedString = Utils.decryptString(encryptedData, password, salt.getBytes(StandardCharsets.UTF_16LE), 282);
        Assert.assertEquals(expectedDecryptedString, actualDecryptedString);
    }

    @Test
    public void encryptAndDecryptedDataTest() throws GeneralSecurityException {
        char[] password = new char[]{'a', 'a', 'a', '0', '0', 'a', 'a', 'a'};
        String salt = "asdf";
        String openText = "0, 0, 0, 0, 0, 0";
        byte[] encryptedData = Utils.encryptString(openText, password, salt.getBytes(StandardCharsets.UTF_16LE), 280);
        String decryptedText = Utils.decryptString(encryptedData, password, salt.getBytes(StandardCharsets.UTF_16LE), 280);
        Assert.assertEquals(openText, decryptedText);
    }

    @Test
    public void loopTest() {
        int iteratedPasswords = 0;
        for (int i = 0; i < Utils.POSSIBLE_CHARS.length; i++) {
            char c1 = Utils.POSSIBLE_CHARS[i];
            for (char c2 : Utils.POSSIBLE_CHARS) {
                for (char c3 : Utils.POSSIBLE_CHARS) {
                    for (char c4 : Utils.POSSIBLE_CHARS) {
                        for (char c5 : Utils.POSSIBLE_CHARS) {
                            for (char c6 : Utils.POSSIBLE_CHARS) {
                                char[] password = new char[]{'l', c1, c2, c3, '4', c4, c5, c6};
                                byte numbers = 0;
                                for (char c : password) {
                                    if (Character.isDigit(c))
                                        numbers++;
                                }
                                if (numbers != 2)
                                    continue;
                                iteratedPasswords++;
                            }
                        }
                    }
                }
            }
        }
        Assert.assertEquals(iteratedPasswords, 712882560);
    }

    @Test
    public void printProvidersTest() {
        Class<?> typeClass = MessageDigest.class;
        for (Provider prov : Security.getProviders()) {
            String type = typeClass.getSimpleName();

            List<Provider.Service> algos = new ArrayList<>();

            Set<Provider.Service> services = prov.getServices();
            for (Provider.Service service : services) {
                if (service.getType().equalsIgnoreCase(type)) {
                    algos.add(service);
                }
            }

            if (!algos.isEmpty()) {
                System.out.printf(" --- Provider %s, version %.2s --- %n", prov.getName(), prov.getVersionStr());
                for (Provider.Service service : algos) {
                    String algo = service.getAlgorithm();
                    System.out.printf("Algorithm name: \"%s\"%n", algo);


                }
            }

            // --- find aliases (inefficiently)
            Set<Object> keys = prov.keySet();
            for (Object key : keys) {
                final String prefix = "Alg.Alias." + type + ".";
                if (key.toString().startsWith(prefix)) {
                    String value = prov.get(key.toString()).toString();
                    System.out.printf("Alias: \"%s\" -> \"%s\"%n",
                            key.toString().substring(prefix.length()),
                            value);
                }
            }
        }
    }
}

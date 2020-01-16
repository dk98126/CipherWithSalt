import org.junit.Assert;
import org.junit.Test;
import salt.and.pepper.Utils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;

public class ControlExampleTest {
    @Test
    public void controlSaltTest() throws NoSuchAlgorithmException {
        String expectedSalt = "asdf";
        String saltHashStr = "87 81 42 98 D7 96 54 DA 79 20 C1 F1 45 F1 4B F5 01 2A E2 F3";
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
    public void checkPBKDF2() {

    }

    @Test
    public void controlEncryptedDataTest() throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        char[] password = new char[]{'a', 'a', 'a', '0', '0', 'a', 'a', 'a'};
        String salt = "asdf";
        String expectedDecryptedString = "0, 0, 0, 0, 0, 0";
        String encryptedDataStr = "33 DD E1 16 67 DE 28 F2 71 92 4B FF BE 4D 4F 65 4E 17 41 BB 40 A5 85 C4 BD FD 7A 4E FB 24 27 4E";
        byte[] encryptedData = Utils.getBytesFromBytesString(encryptedDataStr);
        String actualDecryptedString = Utils.getDecryptedString(encryptedData, salt.getBytes(), 282, password);
        System.out.println(Utils.encryptString(expectedDecryptedString, salt.getBytes(StandardCharsets.UTF_16LE), 282, password));
        Assert.assertEquals(expectedDecryptedString, actualDecryptedString);
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
                System.out.printf(" --- Provider %s, version %.2f --- %n", prov.getName(), prov.getVersion());
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

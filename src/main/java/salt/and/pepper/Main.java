package salt.and.pepper;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

@Slf4j
public class Main {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidKeySpecException, NoSuchPaddingException {
        InputStream inputStream = Main.class.getResourceAsStream("/cipheredText.txt");
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        byte[] initialBytes = Utils.getBytesFromReader(reader);
        log.info("Read number of bytes: " + initialBytes.length);

        byte[] saltHash = Utils.getSaltHash(initialBytes, 20);
        log.info("Salt hash: " + Arrays.toString(saltHash));
        log.info("Salt hash length: " + saltHash.length);

        int counter = Utils.getCounter(initialBytes, 20, 24);
        log.info("counter: " + counter);

        byte[] cipheredText = Utils.getCipheredText(initialBytes, 24);
        log.info("CipheredText: " + Arrays.toString(cipheredText));
        log.info("Ciphered text length: " + cipheredText.length);

        String salt = Utils.getSaltFromHash(saltHash);
        log.info("Salt: " + salt);
        log.info("Salt length: " + salt.length());

        String keyModel = "l***4***";

        Utils.generateBigFileOfDecryptedInfo(cipheredText, salt.getBytes(), counter, "/tmp/texts.txt");
    }
}

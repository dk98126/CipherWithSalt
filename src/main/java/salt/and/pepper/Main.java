package salt.and.pepper;

import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Slf4j
public class Main {
    public static final int THREADS_NUMBER = 4;

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        InputStream inputStream = Main.class.getResourceAsStream("/cipheredText.txt");
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        byte[] initialBytes = Utils.getBytesFromBytesString(reader.readLine());
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

        List<PasswordPicker> passwordPickers = new ArrayList<>();
        for (int i = 0; i < THREADS_NUMBER; i++) {
            passwordPickers.add(new PasswordPicker(Arrays.copyOfRange(cipheredText, 16, 32),
                    Arrays.copyOf(salt.getBytes(), salt.getBytes().length),
                    "/tmp/texts" + (i+1) + ".txt",
                    counter,
                    i,
                    THREADS_NUMBER));
        }

        for (PasswordPicker passwordPicker : passwordPickers) {
            new Thread(passwordPicker).start();
        }
    }
}

package salt.and.pepper;

import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

@Slf4j
public class Main {
    public static void main(String[] args) throws IOException {
        InputStream inputStream = Main.class.getResourceAsStream("/cipheredText.txt");
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        byte[] bytes = getBytesFromReader(reader);
        log.info("Read number of bytes: " + bytes.length);

        String salt = getSaltFromBytes(bytes);
        log.info("Salt: " + salt);
        log.info("Salt length: " + salt.length());

        String cipheredText = getCipheredText(bytes);
        log.info("CipheredText: " + cipheredText);
        log.info("Ciphered text length: " + cipheredText.length());

        log.info("Combined length: " + (salt.length() + cipheredText.length()));
    }

    private static String getCipheredText(byte[] bytes) {
        return new String(Arrays.copyOfRange(bytes, 8, bytes.length), StandardCharsets.UTF_8);
    }

    private static String getSaltFromBytes(byte[] bytes) {
        return new String(Arrays.copyOfRange(bytes, 0, 7), StandardCharsets.UTF_16LE);
    }

    private static byte[] getBytesFromReader(BufferedReader reader) throws IOException {
        String[] bytesInStrings = reader.readLine().split(" ");
        byte[] bytes = new byte[bytesInStrings.length];
        for (int i = 0; i < bytesInStrings.length; i++) {
            bytes[i] = (byte) Integer.parseInt(bytesInStrings[i], 16);
        }
        return bytes;
    }
}

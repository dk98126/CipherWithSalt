package salt.and.pepper;

import lombok.extern.slf4j.Slf4j;

import java.io.*;
import java.util.Arrays;
import java.util.stream.Collectors;

@Slf4j
public class Main {
    public static void main(String[] args) throws IOException {
        InputStream inputStream = Main.class.getResourceAsStream("/cipheredText.txt");
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        log.info("Reading ciphered text file");
        String cipheredText = Arrays.stream(reader.readLine().split(" "))
                .map(i -> String.valueOf((char)Integer.parseUnsignedInt(i, 16)))
                .collect(Collectors.joining());
        log.info("CipheredText: " + cipheredText);
        log.info("Ciphered text length: " + cipheredText.length());
    }
}

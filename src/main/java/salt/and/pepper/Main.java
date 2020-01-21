package salt.and.pepper;

import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class Main {
    public static final int THREADS_NUMBER = 12;

    public static void main(String[] args) {
        byte[] cipheredText = Utils.getBytesFromBytesString("F8 CD F4 D5 29 08 15 28 D4 76 03 6C 5F B7 12 8E 26 36 73 99 6F 67 6C BC 3E 1E 24 3F 36 3F 56 CD");

        if (args.length != 1) {
            log.error("Укажите путь до папки, куда сохранять файлы");
            System.exit(-1);
        }
        String pathToDir = args[0];
        List<PasswordPicker> passwordPickers = new ArrayList<>();
        for (int i = 0; i < THREADS_NUMBER; i++) {
            passwordPickers.add(new PasswordPicker(cipheredText, "acwd".getBytes(StandardCharsets.UTF_16LE),
                    pathToDir + "/texts" + (i + 1) + ".txt",
                    280,
                    i,
                    THREADS_NUMBER));
        }

        for (PasswordPicker passwordPicker : passwordPickers) {
            new Thread(passwordPicker).start();
        }
    }
}

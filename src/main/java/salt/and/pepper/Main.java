package salt.and.pepper;

import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class Main {
    public static final int THREADS_NUMBER = 36;

    public static void main(String[] args) {
        byte[] cipheredText = Utils.getBytesFromBytesString("26 36 73 99 6F 67 6C BC 3E 1E 24 3F 36 3F 56 CD");

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

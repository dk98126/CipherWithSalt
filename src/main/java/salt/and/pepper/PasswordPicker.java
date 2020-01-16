package salt.and.pepper;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class PasswordPicker implements Runnable {
    public PasswordPicker(byte[] cipheredText, byte[] salt, String path, int counter, int thread, int allThreads) {
        this.cipheredText = cipheredText;
        this.salt = salt;
        this.path = path;
        this.counter = counter;
        this.thread = thread;
        this.allThreads = allThreads;
    }

    private byte[] cipheredText;
    private byte[] salt;
    private String path;
    private int counter;
    private int thread;
    private int allThreads;

    @Override
    public void run() {
        try {
            Utils.generateBigFileOfDecryptedInfo(cipheredText, salt, counter, path, thread, allThreads);
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
    }
}

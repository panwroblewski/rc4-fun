import javax.crypto.*;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Main {

    private static final String ENCRYPTION_ALGORITHM = "ARCFOUR";

    public static void main(String[] args) throws Exception {
        KeyGenerator rc4KeyGenerator = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
        SecretKey secretKey = rc4KeyGenerator.generateKey();
        Cipher rc4 = Cipher.getInstance(ENCRYPTION_ALGORITHM);

        String stringFromAlice = "Hello bob, how you doing? Hello bob, how you doing?";

        Map<Integer, List<String>> encryptedMessageFromAlice = encryptMessage(stringFromAlice, secretKey, rc4);
        System.out.println("Encrypted message from Alice: " + encryptedMessageFromAlice);

        char[] decodedMesssage = decryptMessage(encryptedMessageFromAlice, secretKey, rc4);

        System.out.println("Decoded message: ");
        printCharArray(decodedMesssage);
    }

    private static char[] decryptMessage(Map<Integer, List<String>> message, SecretKey secretKey, Cipher rc4) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        char[] decodedMesssage = new char[256];
        for (Integer integer : message.keySet()) {
            for (String character : message.get(integer)) {

                byte[] dehashedValue = encrypt(String.valueOf(character), secretKey, rc4);
                int index = integer - Integer.valueOf(dehashedValue[0]);

                decodedMesssage[index] = character.charAt(0);
            }
        }

        return decodedMesssage;
    }

    private static  Map<Integer, List<String>> encryptMessage(String message, SecretKey secretKey, Cipher rc4) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Map<Integer, List<String>> encryptedMessageFromAlice = new HashMap<>();

        char[] charsFromAlice = message.toCharArray();
        for (int i = 0; i < charsFromAlice.length; i++) {
            byte[] hash = encrypt(String.valueOf(charsFromAlice[i]), secretKey, rc4);
            int indexHash = i + Integer.valueOf(hash[0]);

            List<String> list = encryptedMessageFromAlice.get(indexHash);
            if (list == null) {
                list = new ArrayList<>();
                encryptedMessageFromAlice.put(indexHash, list);
            }
            list.add(String.valueOf(charsFromAlice[i]));
        }

        return encryptedMessageFromAlice;
    }

    private static void printCharArray(char[] arr) {
        for (int i = 0; i < arr.length; i++) {
            System.out.print(arr[i]);
        }
    }

    private static byte[] encrypt(String plaintext, SecretKey secretKey, Cipher rc4) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        rc4.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] plaintextBytes = plaintext.getBytes();
        byte[] ciphertextBytes = rc4.doFinal(plaintextBytes);
        return ciphertextBytes;
    }
}

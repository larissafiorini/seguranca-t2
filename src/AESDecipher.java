import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

/*
 * AES - Decifragem
 * Essa classe realiza a decifragem de um texto cifrado utilizando os modos de operação CTR ou CBC para um texto claro.
 *
 * Autora: Larissa Fiorini Martins
 *
 * */

public class AESDecipher {

    public static final Integer ivSize = 32;

    // Funcao para converter um array de bytes para uma String em hexadecimal
    public static String toHexString(byte[] array) {
        return javax.xml.bind.DatatypeConverter.printHexBinary(array);
    }

    // Funcao para converter uma String em hexadecimal para um array de bytes
    public static byte[] toByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }

    public static String convertHexToString(String hex){
        byte[] s = DatatypeConverter.parseHexBinary(hex);
        return new String(s);
    }

    public static IvParameterSpec extractIV(String cipher_text){
        // hexa: byte = 2 digitos em hexa
        String iv = cipher_text.substring(0, ivSize);
        System.out.println("IV: "+iv);

        byte[] iv_bytes= toByteArray(iv);

        return new IvParameterSpec(iv_bytes);
    }

    public static byte[] extractEncryptedPart(String cipher_text){
        String encrypted_part = cipher_text.substring(ivSize);
        System.out.println("Encrypted part: "+encrypted_part);
        return toByteArray(encrypted_part);
    }

    public static void decrypt(String operation_mode, String cipher_text, String key) throws Exception{
            String aes_op="";
            if (operation_mode.equals("CTR"))
                aes_op = "AES/CTR/NoPadding";
            else if (operation_mode.equals("CBC"))
                aes_op = "AES/CBC/PKCS5Padding";
            else
                System.out.println("Invalid operation mode. Please insert CTR or CBC.");

            Cipher cipher = Cipher.getInstance(aes_op);

            // Extract IV from cipher_text
            IvParameterSpec ivParameterSpec = extractIV(cipher_text);

            // Key
            byte[] key_bytes= toByteArray(key);
            SecretKeySpec skeySpec = new SecretKeySpec(key_bytes, "AES");

            // Decrypt
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParameterSpec);
            // Extract encrypted part without IV and decrypt
            byte[] decrypted_bytes = cipher.doFinal(extractEncryptedPart(cipher_text));

            String plaintext = new String(decrypted_bytes);

            System.out.println("\nTEXTO DECIFRADO: " + plaintext);
    }

}

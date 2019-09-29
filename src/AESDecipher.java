import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.util.Arrays;

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

    //Gera uma chave a partir de uma String.
    //Retorna a chave secreta a partir dos 16 bytes da funcao hash aplicada sobre a String
    public static SecretKeySpec getSecretKey(String passwd) throws Exception{
        byte[] dataBytes = passwd.getBytes();
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        md.update(dataBytes,0,passwd.length());
        byte[] mdbytes=md.digest();

        return new SecretKeySpec(Arrays.copyOfRange(mdbytes,0,16), "AES");
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

            System.out.println("texto decifrado HEXA: "+toHexString(decrypted_bytes));

            String plaintext = new String(decrypted_bytes);

            System.out.println("\nTEXTO DECIFRADO: " + plaintext);
    }

}

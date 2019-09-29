import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.util.Arrays;

public class AESDecipher {

    // Funcao para converter um array de bytes para uma String em hexadecimal
    public static String toHexString(byte[] array) {
        return javax.xml.bind.DatatypeConverter.printHexBinary(array);
    }

    // Funcao para converter uma String em hexadecimal para um array de bytes
    public static byte[] toByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }

    public String convertHexToString(String hex){
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

    public static IvParameterSpec extractIVpart(byte[] texto_cifrado){
        int ivSize = 16;
        // Extract IV.
        byte[] iv = new byte[ivSize];
        System.arraycopy(texto_cifrado, 0, iv, 0, iv.length);

        System.out.println("IV: "+toHexString(iv));
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        return ivParameterSpec;
    }

    public static byte[] extractEncryptedPart(byte[] texto_cifrado)
    {
        int ivSize = 16;
        // Extract encrypted part.
        int encryptedSize = texto_cifrado.length - ivSize;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(texto_cifrado, ivSize, encryptedBytes, 0, encryptedSize);

        return encryptedBytes;
    }

    public static void decryptCTR(byte[] dataBytes, IvParameterSpec ivParameterSpec, byte[] encryptedBytes) throws Exception {
        // Decrypt.
        Cipher cipher_ctr = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKeySpec skeySpec = new SecretKeySpec(dataBytes, "AES");

        cipher_ctr.init(Cipher.DECRYPT_MODE, skeySpec, ivParameterSpec);
        byte[] decrypted = cipher_ctr.doFinal(encryptedBytes);

        String decifrada_hexadecimal = toHexString(decrypted);

        System.out.println("\nMensagem decifrada CTR: "+ (new String(decrypted)));
        System.out.println("\nMensagem decifrada CTR: "+ decifrada_hexadecimal);
//        System.out.println("\nMensagem decifrada CTR: "+ AESdecipher.convertHexToString(decifrada_hexadecimal));

    }

    public static void decryptCBC() throws Exception {
        //Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
    }


}

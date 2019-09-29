import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class App {
    public static void main(String[] args) throws Exception {
        //Recebe dois parametros: senha e uma string para ser CIFRADA com a senha
        AESCipher AEScipher = new AESCipher();
        SecretKeySpec skeySpecCipher = AEScipher.getSecretKey("teste");

        Cipher cipher = Cipher.getInstance("AES");

        cipher.init(Cipher.ENCRYPT_MODE, skeySpecCipher);

        byte[] encrypted = cipher.doFinal("text".getBytes());

        System.out.println("Mensagem cifrada: "+ AEScipher.toHexString(encrypted));


        // Recebe dois parametros: senha e uma string para ser DECIFRADA com a senha
        AESDecipher AESdecipher = new AESDecipher();
        SecretKeySpec skeySpecDecipher = AESdecipher.getSecretKey("teste");

        cipher.init(Cipher.DECRYPT_MODE,skeySpecDecipher);

        byte[] deciphered = cipher.doFinal(AESdecipher.toByteArray("F6686BFD2C360097D742AD1BF5F72338"));

        System.out.println("Mensagem decifrada: "+ (new String(deciphered)));
    }

}

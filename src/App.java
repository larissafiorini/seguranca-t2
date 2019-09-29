import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class App {
    public static void main(String[] args) throws Exception {
        //Recebe dois parametros: senha e uma string para ser CIFRADA com a senha
        AESCipher AEScipher = new AESCipher();
        SecretKeySpec skeySpecCipher = AEScipher.getSecretKey("teste");

        Cipher cipher = Cipher.getInstance("AES");
        //  Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");


        cipher.init(Cipher.ENCRYPT_MODE, skeySpecCipher);

        byte[] encrypted = cipher.doFinal("text".getBytes());

        System.out.println("Mensagem cifrada: "+ AEScipher.toHexString(encrypted));


        // Recebe dois parametros: senha e uma string para ser DECIFRADA com a senha
        AESDecipher AESdecipher = new AESDecipher();
        SecretKeySpec skeySpecDecipher = AESdecipher.getSecretKey("teste");

        cipher.init(Cipher.DECRYPT_MODE,skeySpecDecipher);

        byte[] deciphered = cipher.doFinal(AESdecipher.toByteArray("F6686BFD2C360097D742AD1BF5F72338"));

        System.out.println("Mensagem decifrada: "+ (new String(deciphered)));

        // DECIFRANDO CTR

        // IV de 16 bytes
//        SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
//        byte[] iv = new byte[cipher.getBlockSize()];
//        randomSecureRandom.nextBytes(iv);
//        IvParameterSpec ivParams = new IvParameterSpec(iv);

//        // Generating IV.
//        int ivSize = 16;
//        byte[] iv = new byte[ivSize];
//        SecureRandom random = new SecureRandom();
//        random.nextBytes(iv);
//        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
//
//        System.out.println("IV: "+(new String(ivParameterSpec.getIV())));
//

        // using CTR mode decryption
        byte[] texto_cifrado="770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451".getBytes();
        byte[] dataBytes = "36f18357be4dbd77f050515c73fcf9f2".getBytes();

        IvParameterSpec ivParameterSpec =AESdecipher.extractIVpart(texto_cifrado);

        byte[] encryptedBytes = AESdecipher.extractEncryptedPart(texto_cifrado);

        // Decrypt.
        AESdecipher.decryptCTR(dataBytes,ivParameterSpec,encryptedBytes);

           }

}

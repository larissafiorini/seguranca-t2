import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.SecureRandom;

/*
* AES - Cifragem
* Essa classe realiza a cifragem de um texto em hexadecimal utilizando os modos de operação CTR ou CBC.
*
* Autora: Larissa Fiorini Martins
*
* */

    public class AESCipher {

        // Funcao para converter um array de bytes para uma String em hexadecimal
        public static String toHexString(byte[] array) {
            return DatatypeConverter.printHexBinary(array);
        }

        // Funcao para converter uma String em hexadecimal para um array de bytes
        public static byte[] toByteArray(String s) {
            return DatatypeConverter.parseHexBinary(s);
        }

        public static IvParameterSpec generatingRandomIV(){
            // Generating IV of 16 bytes
            int ivSize = 16;
            byte[] iv = new byte[ivSize];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);


            return ivParameterSpec;
        }

        public static String crypt(String operation_mode, String plain_text, String key) throws Exception{
            String aes_op="";
            if (operation_mode.equals("CTR"))
                aes_op = "AES/CTR/NoPadding";
            else if (operation_mode.equals("CBC"))
                aes_op = "AES/CBC/PKCS5Padding";
            else
                System.out.println("Invalid operation mode. Please insert CTR or CBC.");

            Cipher cipher = Cipher.getInstance(aes_op);

            // Generating IV
            IvParameterSpec ivParameterSpec =generatingRandomIV();
            String hexa_iv = toHexString(ivParameterSpec.getIV());

            System.out.println("\nIV: "+hexa_iv);

            // Key
            SecretKeySpec skeySpecCipher = new SecretKeySpec(toByteArray(key), "AES");

            // Crypt
            cipher.init(Cipher.ENCRYPT_MODE, skeySpecCipher, ivParameterSpec);
            byte[] encrypted_bytes = cipher.doFinal(plain_text.getBytes());

            System.out.println("Encrypted text: " + toHexString(encrypted_bytes));

            // Join IV in hexadecimal with encrypted text in hexadecimal
            String cypher_text = String.join("", hexa_iv, toHexString(encrypted_bytes));

            System.out.println("\nMensagem cifrada: "+ cypher_text);
            return cypher_text;
        }
    }

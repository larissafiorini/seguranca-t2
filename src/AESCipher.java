import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

    public class AESCipher {

        // Funcao para converter um array de bytes para uma String em hexadecimal
        public static String toHexString(byte[] array) {
            return DatatypeConverter.printHexBinary(array);
        }

        // Funcao para converter uma String em hexadecimal para um array de bytes
        public static byte[] toByteArray(String s) {
            return DatatypeConverter.parseHexBinary(s);
        }

        // Gera uma chave a partir de uma String.
        // Retorna a chave secreta a partir dos 16 bytes da funcao hash aplicada sobre a string
        public static SecretKeySpec getSecretKey(String passwd) throws Exception{
            byte[] dataBytes = passwd.getBytes();

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(dataBytes, 0, passwd.length());
            byte[] mdbytes=md.digest();

            return new SecretKeySpec(Arrays.copyOfRange(mdbytes,0,16), "AES");

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

            // Crypt
            SecretKeySpec skeySpecCipher = getSecretKey(key);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpecCipher, ivParameterSpec);
            byte[] encrypted_bytes = cipher.doFinal(plain_text.getBytes());

            System.out.println("Encrypted text: " + toHexString(encrypted_bytes));

            // Join IV in hexadecimal with encrypted text in hexadecimal
            String cypher_text = String.join("", hexa_iv, toHexString(encrypted_bytes));

            System.out.println("\nMensagem cifrada: "+ cypher_text);
            return cypher_text;
        }

    }

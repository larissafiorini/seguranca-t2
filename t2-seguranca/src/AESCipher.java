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

        // Funcao para calcular um IV de 16 bytes de maneira aleatoria
        public static IvParameterSpec generatingRandomIV(){
            int ivSize = 16;
            byte[] iv = new byte[ivSize];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            return ivParameterSpec;
        }

        // Funcao para cifrar usando AES com os modos de operacao CTR e CBC
        public static String crypt(String operation_mode, String plain_text, String key) throws Exception{
            String aes_op="";
            if (operation_mode.equals("CTR"))
                aes_op = "AES/CTR/NoPadding";
            else if (operation_mode.equals("CBC"))
                aes_op = "AES/CBC/PKCS5Padding";
            else
                System.out.println("Modo de operacao invalido. Por favor insira 'CTR' ou 'CBC'.");

            Cipher cipher = Cipher.getInstance(aes_op);

            // Gera IV
            IvParameterSpec ivParameterSpec =generatingRandomIV();
            String hexa_iv = toHexString(ivParameterSpec.getIV());

            // Chave
            SecretKeySpec skeySpecCipher = new SecretKeySpec(toByteArray(key), "AES");

            // Cifra utilizando a chave e o IV
            cipher.init(Cipher.ENCRYPT_MODE, skeySpecCipher, ivParameterSpec);
            byte[] encrypted_bytes = cipher.doFinal(plain_text.getBytes());

            // Anexa o IV em hexadecimal gerado na frente do texto cifrado em hexadecimal
            String cypher_text = String.join("", hexa_iv, toHexString(encrypted_bytes));

            System.out.println("\nMensagem cifrada: "+ cypher_text);
            return cypher_text;
        }
    }
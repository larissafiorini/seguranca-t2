
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
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

    }

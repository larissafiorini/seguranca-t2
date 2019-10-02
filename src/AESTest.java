import org.junit.jupiter.api.Test;

/*
 * Essa classe contem um teste unitario para cada tarefa de cifragem/decifragem proposta no trabalho.
 *
 * Autora: Larissa Fiorini Martins
 *
 * */

class AESTest {

    @Test
    void tarefa1() {
        System.out.println("Tarefa 1: Decifrar com modo de operacao CBC");
        try {
            String key = "140b41b22a29beb4061bda66b6747e14";
            String cbc_ciphertext = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";

            System.out.println("\nKey: "+ key);
            System.out.println("Ciphertext: "+ cbc_ciphertext);

            AESDecipher aes = new AESDecipher();
            aes.decrypt("CBC", cbc_ciphertext, key);

        }catch (Exception e){
        }

    }

    @Test
    void tarefa2() {
        System.out.println("Tarefa 2: Decifrar com modo de operacao CBC");
        try {
            String key = "140b41b22a29beb4061bda66b6747e14";
            String cbc_ciphertext ="5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253";

            System.out.println("\nKey: "+ key);
            System.out.println("Ciphertext: "+ cbc_ciphertext);

            AESDecipher aes = new AESDecipher();
            aes.decrypt("CBC", cbc_ciphertext, key);

        }catch (Exception e){
        }
    }

    @Test
    void tarefa3() {
        System.out.println("Tarefa 3: Decifrar com modo de operacao CTR");
        try {
            String key ="36f18357be4dbd77f050515c73fcf9f2";
            String ctr_ciphertext = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329";

            System.out.println("\nKey: "+ key);
            System.out.println("Ciphertext: "+ ctr_ciphertext);

            AESDecipher aes = new AESDecipher();
            aes.decrypt("CTR", ctr_ciphertext, key);

        }catch (Exception e){
        }
    }

    @Test
    void tarefa4() {
        System.out.println("Tarefa 4: Decifrar com modo de operacao CTR");
        try {
            String key ="36f18357be4dbd77f050515c73fcf9f2";
            String ctr_ciphertext ="770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451";

            System.out.println("\nKey: "+ key);
            System.out.println("Ciphertext: "+ ctr_ciphertext);

            AESDecipher aes = new AESDecipher();
            aes.decrypt("CTR", ctr_ciphertext, key);

        }catch (Exception e){
        }
    }

    @Test
    void tarefa5() {
        System.out.println("Tarefa 5: Cifrar com modo de operacao CTR");
        try {
            String key ="36f18357be4dbd77f050515c73fcf9f2";
            String ctr_plaintext ="5468697320697320612073656e74656e636520746f20626520656e63727970746564207573696e672041455320616e6420435452206d6f64652e";

            System.out.println("\nKey: "+key);
            System.out.println("Plaintext: "+ctr_plaintext);

            AESCipher aes = new AESCipher();
            String cipher_text = aes.crypt("CTR", ctr_plaintext, key);

            AESDecipher aes_decipher = new AESDecipher();
            aes_decipher.decrypt("CTR", cipher_text, key);

        }catch (Exception e){
        }
    }

    @Test
    void tarefa6() {
        System.out.println("Tarefa 6: Cifrar com modo de operacao CBC");
        try {
            String key ="140b41b22a29beb4061bda66b6747e14";
            String cbc_plainttext ="4e657874205468757273646179206f6e65206f66207468652062657374207465616d7320696e2074686520776f726c642077696c6c2066616365206120626967206368616c6c656e676520696e20746865204c696265727461646f72657320646120416d6572696361204368616d70696f6e736869702e";

            AESCipher aes = new AESCipher();
            System.out.println("\nKey: "+key);
            System.out.println("Plaintext: "+cbc_plainttext);

            String cipher_text = aes.crypt("CBC", cbc_plainttext, key);

            AESDecipher aes_decipher = new AESDecipher();
            aes_decipher.decrypt("CBC", cipher_text, key);

        }catch (Exception e){
        }
    }


}
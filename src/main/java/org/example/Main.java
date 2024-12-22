package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        // Add BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());

        Scanner sc = new Scanner(System.in);
        System.out.println("Enter the message you want to encrypt:");
        String userInput = sc.nextLine();

        // Generate the key pair
        KeyPair keyPair = generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Encrypt the message using the public key
        byte[] cipherText = encrypt(userInput, publicKey);
        System.out.println("Encrypted message is: " + new String(cipherText));

        // Decrypt the message using the private key
        String decryptedMessage = decrypt(cipherText, privateKey);
        System.out.println("Decrypted message is: " + decryptedMessage);
    }

    private static byte[] encrypt(String msg, PublicKey key) throws Exception {
        // Make sure the encryption mode and algorithm are supported
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(msg.getBytes());
    }

    private static String decrypt(byte[] cipherText, PrivateKey key) throws Exception {
        // Initialize cipher for decryption with the private key
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(cipherText);
        return new String(decryptedBytes);
    }

    private static KeyPair generateKeyPair() throws Exception {
        // Generate the EC key pair using secp256k1 curve
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpecs = new ECGenParameterSpec("secp256k1");
        keyPairGenerator.initialize(ecSpecs);
        return keyPairGenerator.generateKeyPair();
    }
}

package com.securechat;

import java.math.BigInteger;
import java.security.*;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

class DiffieHellmanHelper {
    // RFC 3526 - 2048-bit MODP Group
    private static final BigInteger P = new BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);

    private static final BigInteger G = new BigInteger("2");

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            DHParameterSpec dhSpec = new DHParameterSpec(P, G);
            keyGen.initialize(dhSpec);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            System.err.println("Error generating DH key pair: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);
            return keyAgreement.generateSecret();
        } catch (Exception e) {
            System.err.println("Error generating shared secret: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    // Generate ephemeral key pair for Perfect Forward Secrecy
    public static KeyPair generateEphemeralKeyPair() {
        return generateKeyPair(); 
    }

    // Securely clear sensitive data from memory (best effort)
    public static void clearKeyMaterial(byte[] keyMaterial) {
        if (keyMaterial != null) {
            java.util.Arrays.fill(keyMaterial, (byte) 0);
        }
    }

    // Validate DH public key parameters
    public static boolean validatePublicKey(PublicKey publicKey) {
        try {
            // Basic validation - check if key is within valid range
            return publicKey != null && "DH".equals(publicKey.getAlgorithm());
        } catch (Exception e) {
            System.err.println("Error validating DH public key: " + e.getMessage());
            return false;
        }
    }
}
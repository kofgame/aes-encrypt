package com.home.encrypt.service;

import com.google.common.base.Charsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.*;


public class CookieEncryptionServiceImpl implements CookieEncryptionService {

    private static final String ENCRYPTION_ALGORITHM = "AES";
    public static final String HASH_ALGORITHM = "MD5";
    private static final Charset DEFAULT_CHARSET = Charsets.UTF_8;


    private static final Logger LOG = LoggerFactory.getLogger(CookieEncryptionServiceImpl.class);

    @Override
    public String encryptCookie(String cookieValue, String ipAddress, String browserId) {
        try {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            SecretKeySpec key = generateKey(ipAddress, browserId);
            initCipher(cipher, key, Cipher.ENCRYPT_MODE);
            byte[] encryptedValue = cipher.doFinal(cookieValue.getBytes(DEFAULT_CHARSET));
            return new BASE64Encoder().encode(encryptedValue);
        } catch (GeneralSecurityException exc) {
            LOG.error("Cannot encrypt cookieValue: '{}'",  cookieValue, exc);
            throw new SecurityException("Cannot encrypt cookieValue due:", exc);
        }
    }

    @Override
    public String decryptCookie(String encryptedCookie, String ipAddress, String browserId) {
        try {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            SecretKeySpec key = generateKey(ipAddress, browserId);
            initCipher(cipher, key, Cipher.DECRYPT_MODE);
            byte[] decodedValue = new BASE64Decoder().decodeBuffer(encryptedCookie);
            return new String(cipher.doFinal(decodedValue));
        } catch (GeneralSecurityException | IOException exc) {
            LOG.error("Cannot decrypt cookieValue: '{}'",  encryptedCookie, exc);
            throw new SecurityException("Cannot decrypt cookieValue due:", exc);
        }
    }

    private void initCipher(Cipher cipher, SecretKey secretKey, int mode) throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.init(mode, secretKey);
    }

    private SecretKeySpec generateKey(String ipAddress, String browserId) throws NoSuchAlgorithmException {
        byte[] compoundKey = ipAddress.concat(browserId).getBytes(DEFAULT_CHARSET);
        byte[] keyHash = convertToHash(compoundKey);
        SecretKeySpec key = new SecretKeySpec(keyHash, ENCRYPTION_ALGORITHM);
        return key;
    }

    /**
     * Hashes @param message to 32 bytes length (since AES allows 16, 24 or 32 byte key length)
     * and thus prevents invalid AES key length exception
     * @param message
     * @return hashed message
     * @throws NoSuchAlgorithmException
     */
    private byte[] convertToHash(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
        return md.digest(message);
    }
}
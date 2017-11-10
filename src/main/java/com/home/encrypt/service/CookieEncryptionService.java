package com.home.encrypt.service;

public interface CookieEncryptionService {

    /**
     * Encrypts cookieValue, using provided ipAddress and browserId as compound key
     * @param cookieValue value to encrypt
     * @param ipAddress user's ipAddress
     * @param browserId user's browserId
     * @return encrypted value
     */
    String encryptCookie(String cookieValue, String ipAddress, String browserId);

    /**
     * Decrypts encryptedCookie, using provided ipAddress and browserId as compound key
     * @param encryptedCookie encrypted value
     * @param ipAddress user's ipAddress
     * @param browserId user's browserId
     * @return decrypted value
     */
    String decryptCookie(String encryptedCookie, String ipAddress, String browserId);

}
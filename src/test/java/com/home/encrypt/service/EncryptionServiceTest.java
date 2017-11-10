package com.home.encrypt.service;

import org.junit.Assert;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;


public class EncryptionServiceTest {

    public static final String TEST_IP_ADDRESS = "localhost";
    public static final String TEST_BROWSER_ID = "Chrome/61.0.3163.10012345";

    private EncryptionServiceImpl sut = new EncryptionServiceImpl();

    @Test
    public void shouldEncryptAndDecryptToOriginalValue() throws NoSuchAlgorithmException {

        String cookieValue = "aCookieValue";

        String encryptedCookie = sut.encryptCookie(cookieValue, TEST_IP_ADDRESS, TEST_BROWSER_ID);
        String decryptedCookie = sut.decryptCookie(encryptedCookie, TEST_IP_ADDRESS, TEST_BROWSER_ID);

        Assert.assertEquals(cookieValue, decryptedCookie);
    }

}
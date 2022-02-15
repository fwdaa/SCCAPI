package aladdin.capi.ansi.pkcs11;
import aladdin.capi.pkcs11.*; 

public class Test extends aladdin.capi.ansi.Test
{
    ///////////////////////////////////////////////////////////////////////
    // Выполнить тесты
    ///////////////////////////////////////////////////////////////////////
    public static void testAlgorithms(Applet applet) throws Exception
    {
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_MD2, 0, 0))
        {
            // выполнить тест
            testMD2(applet.provider(), applet);
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_MD5, 0, 0))
        {
            // выполнить тест
            testMD5     (applet.provider(), applet);
            testHMAC_MD5(applet.provider(), applet);
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_RIPEMD128, 0, 0))
        {
            // выполнить тест
            testRIPEMD128     (applet.provider(), applet);
            testHMAC_RIPEMD128(applet.provider(), applet);
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_RIPEMD160, 0, 0))
        {
            // выполнить тест
            testRIPEMD160     (applet.provider(), applet);
            testHMAC_RIPEMD160(applet.provider(), applet);
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_SHA_1, 0, 0))
        {
            // выполнить тест
            testSHA1     (applet.provider(), applet);
            testHMAC_SHA1(applet.provider(), applet);
            
            // при поддержке алгоритма
            if (applet.supported(aladdin.pkcs11.API.CKM_PKCS5_PBKD2, 0, 0))
            { 
                // выполнить тест
                testPBKDF2_HMAC_SHA1(applet.provider(), applet); 
            }
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_SHA224, 0, 0))
        {
            // выполнить тест
            testSHA2_224     (applet.provider(), applet);
            testHMAC_SHA2_224(applet.provider(), applet);
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_SHA256, 0, 0))
        {
            // выполнить тест
            testSHA2_256     (applet.provider(), applet);
            testHMAC_SHA2_256(applet.provider(), applet);
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_SHA384, 0, 0))
        {
            // выполнить тест
            testSHA2_384     (applet.provider(), applet);
            testHMAC_SHA2_384(applet.provider(), applet);
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_SHA512, 0, 0))
        {
            // выполнить тест
            testSHA2_512     (applet.provider(), applet);
            testHMAC_SHA2_512(applet.provider(), applet);
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_RC2_ECB, 0, 0))
        {
            // выполнить тест
            testRC2    (applet.provider(), applet);
            testWrapRC2(applet.provider(), applet);
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_RC4, 0, 0))
        {
            // выполнить тест
            testRC4(applet.provider(), applet);
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_RC5_ECB, 0, 0))
        {
            // выполнить тест
            testRC5(applet.provider(), applet);
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_DES_ECB, 0, 0))
        {
            // выполнить тест
            testDES          (applet.provider(), applet);
            testWrapSMIME_DES(applet.provider(), applet);
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_DES_MAC_GENERAL, 0, 0))
        {
            // выполнить тест
            testCBCMAC_DES(applet.provider(), applet, 8);
            testCBCMAC_DES(applet.provider(), applet, 4);
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_DES_MAC, 0, 0))
        {
            // выполнить тест
            testCBCMAC_DES(applet.provider(), applet, 4);
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_DES3_ECB, 0, 0))
        {
            // выполнить тест
            testTDES          (applet.provider(), applet);
            testWrapSMIME_TDES(applet.provider(), applet);
            testWrapTDES      (applet.provider(), applet);
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_AES_ECB, 0, 0))
        {
            // выполнить тест
            testAES    (applet.provider(), applet);
            testWrapAES(applet.provider(), applet);
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_AES_CMAC, 0, 0))
        {
            // выполнить тест
            testCMAC_AES(applet.provider(), applet);
        }
    }
}

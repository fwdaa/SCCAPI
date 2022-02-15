using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11
{
    public class Test : CAPI.ANSI.Test
    {
        ///////////////////////////////////////////////////////////////////////
        // Выполнить тесты
        ///////////////////////////////////////////////////////////////////////
        public static void TestAlgorithms(CAPI.PKCS11.Applet applet)
        {
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_MD2, 0, 0))
            {
                // выполнить тест
                TestMD2(applet.Provider, applet);
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_MD5, 0, 0))
            {
                // выполнить тест
                TestMD5     (applet.Provider, applet);
                TestHMAC_MD5(applet.Provider, applet);
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_RIPEMD128, 0, 0))
            {
                // выполнить тест
                TestRIPEMD128     (applet.Provider, applet);
                TestHMAC_RIPEMD128(applet.Provider, applet);
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_RIPEMD160, 0, 0))
            {
                // выполнить тест
                TestRIPEMD160     (applet.Provider, applet);
                TestHMAC_RIPEMD160(applet.Provider, applet);
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_SHA_1, 0, 0))
            {
                // выполнить тест
                TestSHA1     (applet.Provider, applet);
                TestHMAC_SHA1(applet.Provider, applet);

                // при поддержке алгоритма
                if (applet.Supported(API.CKM_PKCS5_PBKD2, 0, 0))
                { 
                    // выполнить тест
                    TestPBKDF2_HMAC_SHA1(applet.Provider, applet); 
                }
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_SHA224, 0, 0))
            {
                // выполнить тест
                TestSHA2_224     (applet.Provider, applet);
                TestHMAC_SHA2_224(applet.Provider, applet);
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_SHA256, 0, 0))
            {
                // выполнить тест
                TestSHA2_256     (applet.Provider, applet);
                TestHMAC_SHA2_256(applet.Provider, applet);
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_SHA384, 0, 0))
            {
                // выполнить тест
                TestSHA2_384     (applet.Provider, applet);
                TestHMAC_SHA2_384(applet.Provider, applet);
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_SHA512, 0, 0))
            {
                // выполнить тест
                TestSHA2_512     (applet.Provider, applet);
                TestHMAC_SHA2_512(applet.Provider, applet);
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_RC2_ECB, 0, 0))
            {
                // выполнить тест
                TestRC2    (applet.Provider, applet);
                TestWrapRC2(applet.Provider, applet);
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_RC4, 0, 0))
            {
                // выполнить тест
                TestRC4(applet.Provider, applet);
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_RC5_ECB, 0, 0))
            {
                // выполнить тест
                TestRC5(applet.Provider, applet);
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_DES_ECB, 0, 0))
            {
                // выполнить тест
                TestDES          (applet.Provider, applet);
                TestWrapSMIME_DES(applet.Provider, applet);
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_DES_MAC_GENERAL, 0, 0))
            {
                // выполнить тест
                TestCBCMAC_DES(applet.Provider, applet, 8);
                TestCBCMAC_DES(applet.Provider, applet, 4);
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_DES_MAC, 0, 0))
            {
                // выполнить тест
                TestCBCMAC_DES(applet.Provider, applet, 4);
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_DES3_ECB, 0, 0))
            {
                // выполнить тест
                TestTDES          (applet.Provider, applet);
                TestWrapSMIME_TDES(applet.Provider, applet);
                TestWrapTDES      (applet.Provider, applet);
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_AES_ECB, 0, 0))
            {
                // выполнить тест
                TestAES    (applet.Provider, applet);
                TestWrapAES(applet.Provider, applet);
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_AES_CMAC, 0, 0))
            {
                // выполнить тест
                TestCMAC_AES(applet.Provider, applet);
            }
        }
    }
}

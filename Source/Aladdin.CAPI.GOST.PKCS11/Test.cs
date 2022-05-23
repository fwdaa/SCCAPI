using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.GOST.PKCS11
{
    public class Test : CAPI.GOST.Test
    {
        ///////////////////////////////////////////////////////////////////////
        // Выполнить тесты
        ///////////////////////////////////////////////////////////////////////
        public static void TestAlgorithms(
            CAPI.PKCS11.Applet applet, string[] hashOIDs, string[] sboxOIDs)
        {
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_GOSTR3411, 0, 0))
            {
                for (int i = 0; i < hashOIDs.Length; i++)
                {
                    // выполнить тест
                    TestGOSTR3411_1994     (applet.Provider, applet, hashOIDs[i]); 
                    TestHMAC_GOSTR3411_1994(applet.Provider, applet, hashOIDs[i]); 
                }
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_GOSTR3411_12_256, 0, 0))
            {
                // выполнить тест
                TestGOSTR3411_2012_256     (applet.Provider, applet); 
                TestHMAC_GOSTR3411_2012_256(applet.Provider, applet); 
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_GOSTR3411_12_512, 0, 0))
            {
                // выполнить тест
                TestGOSTR3411_2012_512     (applet.Provider, applet); 
                TestHMAC_GOSTR3411_2012_512(applet.Provider, applet); 
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_GOST28147_ECB, 0, 0))
            {
                for (int i = 0; i < sboxOIDs.Length; i++)
                {
                    // выполнить тест
                    // TestGOST28147(applet.Provider, applet, sboxOIDs[i]);                     
                }
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_GOST28147_MAC, 0, 0))
            {
                for (int i = 0; i < sboxOIDs.Length; i++)
                {
                    // выполнить тест
                    TestMAC_GOST28147(applet.Provider, applet, sboxOIDs[i]); 
                }
            }
            // при поддержке алгоритма
            if (applet.Supported(API.CKM_KDF_GOSTR3411_2012_256, 0, 0))
            {
                // выполнить тест
                TestKDF_GOSTR3411_2012(applet.Provider, applet); 
            }
        }
    }
}

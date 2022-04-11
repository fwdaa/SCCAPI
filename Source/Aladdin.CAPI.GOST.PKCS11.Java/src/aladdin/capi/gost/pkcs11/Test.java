package aladdin.capi.gost.pkcs11;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.capi.gost.pkcs11.cipher.*; 

public class Test extends aladdin.capi.gost.Test
{
    ///////////////////////////////////////////////////////////////////////
    // Выполнить тесты
    ///////////////////////////////////////////////////////////////////////
    public static void testAlgorithms(Applet applet, 
        String[] hashOIDs, String[] sboxOIDs) throws Exception
    {
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_GOSTR3411, 0, 0))
        {
            for (int i = 0; i < hashOIDs.length; i++)
            {
                // выполнить тест
                testGOSTR3411_1994     (applet.provider(), applet, hashOIDs[i]); 
                testHMAC_GOSTR3411_1994(applet.provider(), applet, hashOIDs[i]); 
            }
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_GOSTR3411_12_256, 0, 0))
        {
            // выполнить тест
            testGOSTR3411_2012_256     (applet.provider(), applet); 
            testHMAC_GOSTR3411_2012_256(applet.provider(), applet); 
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_GOSTR3411_12_512, 0, 0))
        {
            // выполнить тест
            testGOSTR3411_2012_512     (applet.provider(), applet); 
            testHMAC_GOSTR3411_2012_512(applet.provider(), applet); 
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_GOST28147_ECB, 0, 0))
        {
            for (int i = 0; i < sboxOIDs.length; i++)
            {
                // выполнить тест
                testGOST28147(applet.provider(), applet, sboxOIDs[i]);                     
            }
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_GOST28147_MAC, 0, 0))
        {
            for (int i = 0; i < sboxOIDs.length; i++)
            {
                // выполнить тест
                testMAC_GOST28147(applet.provider(), applet, sboxOIDs[i]); 
            }
        }
        // при поддержке алгоритма
        if (applet.supported(aladdin.pkcs11.API.CKM_KDF_GOSTR3411_2012_256, 0, 0))
        {
            // выполнить тест
            testKDF_GOSTR3411_2012(applet.provider(), applet); 
        }
    }
}

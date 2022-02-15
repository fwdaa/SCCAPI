package aladdin.capi.kz;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.kz.*;
import aladdin.capi.*; 
import aladdin.capi.Factory; 

public final class Test extends aladdin.capi.Test
{
    public static void main(String[] parameters) throws Exception
    {
        try (Factory factory = new aladdin.capi.kz.Factory()) 
        {
            SecurityStore scope = null; 
            
            ////////////////////////////////////////////////////////////////////
            // Алгоритмы хэширования
            ////////////////////////////////////////////////////////////////////
            aladdin.capi.ansi.Test.testSHA1    (factory, scope);
            aladdin.capi.ansi.Test.testSHA2_224(factory, scope);
            aladdin.capi.ansi.Test.testSHA2_256(factory, scope);
            aladdin.capi.ansi.Test.testSHA2_384(factory, scope);
            aladdin.capi.ansi.Test.testSHA2_512(factory, scope);

            aladdin.capi.gost.Test.testGOSTR3411_1994(
                factory, scope, aladdin.asn1.gost.OID.HASHES_TEST
            ); 
            aladdin.capi.gost.Test.testGOSTR3411_1994(
                factory, scope, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO
            ); 
            testGOST34311_1994(factory, scope); 
            
            ////////////////////////////////////////////////////////////////////
            // Алгоритмы вычисления имитовставки
            ////////////////////////////////////////////////////////////////////
            aladdin.capi.ansi.Test.testHMAC_SHA1    (factory, scope); 
            aladdin.capi.ansi.Test.testHMAC_SHA2_224(factory, scope); 
            aladdin.capi.ansi.Test.testHMAC_SHA2_256(factory, scope); 
            aladdin.capi.ansi.Test.testHMAC_SHA2_384(factory, scope); 
            aladdin.capi.ansi.Test.testHMAC_SHA2_512(factory, scope); 
            
            aladdin.capi.gost.Test.testHMAC_GOSTR3411_1994(
                factory, scope, aladdin.asn1.gost.OID.HASHES_TEST
            ); 
            aladdin.capi.gost.Test.testHMAC_GOSTR3411_1994(
                factory, scope, aladdin.asn1.gost.OID.HASHES_CRYPTOPRO
            ); 
            ////////////////////////////////////////////////////////////////////
            // Алгоритмы шифрования
            ////////////////////////////////////////////////////////////////////
            aladdin.capi.ansi.Test.testRC2 (factory, scope); 
            aladdin.capi.ansi.Test.testRC4 (factory, scope); 
            aladdin.capi.ansi.Test.testTDES(factory, scope); 
            aladdin.capi.ansi.Test.testAES (factory, scope); 
            
            testGOST28147(factory, scope); 
            
            // указать генератор случайных данных
            try (IRand rand = new aladdin.capi.Rand(null))
            {
                ////////////////////////////////////////////////////////////////////
                // RSA
                ////////////////////////////////////////////////////////////////////
                int[] кeySizes = KeySizes.range(1, 32); 

                testRSA(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.GAMMA_KEY_RSA_1024, кeySizes
                ); 
                testRSA(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.GAMMA_KEY_RSA_1536, кeySizes
                ); 
                testRSA(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.GAMMA_KEY_RSA_2048, кeySizes
                ); 
                testRSA(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.GAMMA_KEY_RSA_1024_XCH, кeySizes
                ); 
                testRSA(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.GAMMA_KEY_RSA_1536_XCH, кeySizes
                ); 
                testRSA(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.GAMMA_KEY_RSA_2048_XCH, кeySizes
                ); 
                ////////////////////////////////////////////////////////////////////
                // ГОСТ 34310
                ////////////////////////////////////////////////////////////////////
                testGOST34310(factory, scope, rand, 
                    true, KeyFlags.NONE, OID.GAMMA_KEY_EC256_512_A
                ); 
                testGOST34310(factory, scope, rand, 
                    true, KeyFlags.NONE, OID.GAMMA_KEY_EC256_512_B
                ); 
                testGOST34310(factory, scope, rand, 
                    true, KeyFlags.NONE, OID.GAMMA_KEY_EC256_512_C
                ); 
                testGOST34310(factory, scope, rand, 
                    true, KeyFlags.NONE, OID.GAMMA_KEY_EC256_512_A_XCH
                ); 
                testGOST34310(factory, scope, rand, 
                    true, KeyFlags.NONE, OID.GAMMA_KEY_EC256_512_B_XCH
                ); 
            }
        }
        catch (Throwable e) { e.printStackTrace(System.err); throw e; }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Алгоритмы хэширования
    ////////////////////////////////////////////////////////////////////////////
    public static void testGOST34311_1994(
        Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.GOST34311");
        
        // указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GAMMA_GOST34311_95), Null.INSTANCE
        ); 
        // создать алгоритм хэширования
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class)) 
        {
            // выполнить тест
            aladdin.capi.gost.hash.GOSTR3411_1994.testTest(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.kz.Factory()) 
            {
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Алгоритмы шифрования
    ////////////////////////////////////////////////////////////////////////////
    public static void testGOST28147(Factory factory, SecurityStore scope) throws Exception
    {
        println("Cipher.GOST28147"); byte[] iv = new byte[8]; 
        
        // указать допустимые размеры
        int[] dataSizes = new int[] { 0, 1, 7, 8, 9, 15, 16, 17, 1023, 1024, 1025 }; 
        
        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GAMMA_CIPHER_GOST_ECB), Null.INSTANCE
        ); 
        // создать алгоритм шифрования
        try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        { 
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.kz.Factory()) 
            {
                // выполнить тест
                cipherTest(cipher, PaddingMode.PKCS5, trustFactory, null, parameters, dataSizes);
            }
        }
        // сгенерировать синхропосылку
        generate(iv, 0, iv.length);

        // указать параметры алгоритма
        parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GAMMA_CIPHER_GOST_CBC), new OctetString(iv)
        ); 
        // создать алгоритм шифрования
        try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        { 
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.kz.Factory()) 
            {
                // выполнить тест
                cipherTest(cipher, PaddingMode.PKCS5, trustFactory, null, parameters, dataSizes);
            }
        }
        // сгенерировать синхропосылку
        generate(iv, 0, iv.length);

        // указать параметры алгоритма
        parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GAMMA_CIPHER_GOST_CFB), new OctetString(iv)
        ); 
        // создать алгоритм шифрования
        try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        { 
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.kz.Factory()) 
            {
                // выполнить тест
                cipherTest(cipher, PaddingMode.ANY, trustFactory, null, parameters, dataSizes);
            }
        }
        // сгенерировать синхропосылку
        generate(iv, 0, iv.length); 

        // указать параметры алгоритма
        parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GAMMA_CIPHER_GOST_CNT), new OctetString(iv)
        ); 
        // создать алгоритм шифрования
        try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        { 
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.kz.Factory()) 
            {
                // выполнить тест
                cipherTest(cipher, PaddingMode.ANY, trustFactory, null, parameters, dataSizes);
            }
        }
        // сгенерировать синхропосылку
        generate(iv, 0, iv.length); 

        // указать параметры алгоритма
        parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GAMMA_CIPHER_GOST_OFB), new OctetString(iv)
        ); 
        // создать алгоритм шифрования
        try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        { 
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.kz.Factory()) 
            {
                // выполнить тест
                cipherTest(cipher, PaddingMode.ANY, trustFactory, null, parameters, dataSizes);
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // RSA
    ////////////////////////////////////////////////////////////////////////////
    public static void testRSA(Factory factory, SecurityObject scope, 
        IRand rand, boolean generate, KeyFlags keyFlags, 
        String keyOID, int[] keySizes) throws Exception
    {
        println("RSA/%1$s", keyOID);
        
        // указать доверенную фабрику
        try (Factory trustFactory = new aladdin.capi.kz.Factory()) 
        {
            // получить фабрику кодирования ключей
            KeyFactory keyFactory = trustFactory.getKeyFactory(keyOID); 

            // указать способ использования ключа
            KeyUsage keyUsage = keyFactory.getKeyUsage(); 

            // указать параметры алгоритма
            IParameters parameters = keyFactory.decodeParameters(Null.INSTANCE); 

            // сгенерировать ключевую пару
            try (KeyPair keyPair = generateKeyPair(
                factory, scope, rand, trustFactory, null, generate, 
                keyOID, parameters, keyUsage, keyFlags))
            { 
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.DIGITAL_SIGNATURE))
                { 
                    // выполнить тесты
                    aladdin.capi.ansi.Test.testSignRSA(
                        trustFactory, null, keyPair, keyFlags
                    ); 
                }
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.DATA_ENCIPHERMENT) ||
                    keyUsage.contains(KeyUsage.KEY_ENCIPHERMENT))
                { 
                    // выполнить тесты
                    aladdin.capi.ansi.Test.testKeyxRSA(
                        trustFactory, null, keyPair, keyFlags, keySizes
                    ); 
                }
            }
            // удалить ключи контейнера
            finally { deleteKeys(scope); }
        }
        println();
    }
    ////////////////////////////////////////////////////////////////////////////
    // ГОСТ P 34.10-2001
    ////////////////////////////////////////////////////////////////////////////
    public static void testGOST34310(Factory factory, SecurityObject scope, 
        IRand rand, boolean generate, KeyFlags keyFlags, String keyOID) throws Exception
    {
        println("GOST34310/%1$s", keyOID);
        
        // указать доверенную фабрику
        try (Factory trustFactory = new aladdin.capi.kz.Factory()) 
        {
            // получить фабрику кодирования ключей
            KeyFactory keyFactory = trustFactory.getKeyFactory(keyOID); 

            // указать способ использования ключа
            KeyUsage keyUsage = keyFactory.getKeyUsage(); 

            // указать параметры алгоритма
            IParameters parameters = keyFactory.decodeParameters(Null.INSTANCE); 

            // сгенерировать ключевую пару
            try (KeyPair keyPair = generateKeyPair(
                factory, scope, rand, trustFactory, null, generate, 
                keyOID, parameters, keyUsage, keyFlags))
            { 
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.DIGITAL_SIGNATURE))
                { 
                    // указать параметры алгоритма
                    AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GAMMA_GOST34310_2004), Null.INSTANCE
                    ); 
                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GAMMA_GOST34311_95), Null.INSTANCE
                    ); 
                    // указать параметры алгоритма
                    AlgorithmIdentifier signParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GAMMA_GOST34310_34311_2004_T), null
                    ); 
                    // выполнить тест
                    signTest(trustFactory, null, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags 
                    );
                    // указать параметры алгоритма хэширования
                    hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.gost.OID.GOSTR3411_94), 
                        new ObjectIdentifier(aladdin.asn1.gost.OID.HASHES_CRYPTOPRO) 
                    ); 
                    // указать параметры алгоритма
                    signParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GAMMA_GOSTR3410_R3411_2001_CP), null
                    ); 
                    // выполнить тест
                    signTest(trustFactory, null, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags 
                    );
                }
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.KEY_AGREEMENT))
                { 
                    // закодировать параметры алгоритма 
                    AlgorithmIdentifier agreementParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GAMMA_GOST28147), Null.INSTANCE
                    ); 
                    // выполнить тест
                    aladdin.capi.gost.Test.testAgreementGOSTR3410(
                        trustFactory, null, keyPair, keyFlags, 
                        null, agreementParameters, new int[] {32}
                    ); 
                }
            }
            // удалить ключи контейнера
            finally { deleteKeys(scope); }
        }
        println();
    }
}

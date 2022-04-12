package aladdin.capi.ansi;
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import aladdin.asn1.iso.*;
import aladdin.asn1.ansi.*;
import aladdin.capi.*;
import aladdin.capi.Factory;

public class Test extends aladdin.capi.Test
{
    ///////////////////////////////////////////////////////////////////////
    // Выполнить тесты
    ///////////////////////////////////////////////////////////////////////
    public static void main(String[] parameters) throws Exception
    {
        try (Factory factory = new aladdin.capi.ansi.Factory()) 
        { 
            SecurityStore scope = null; 
            
            ////////////////////////////////////////////////////////////////////
            // Алгоритмы хэширования
            ////////////////////////////////////////////////////////////////////
            testMD2      (factory, scope);
            testMD4      (factory, scope);
            testMD5      (factory, scope);
            testRIPEMD128(factory, scope);
            testRIPEMD160(factory, scope);
            testRIPEMD256(factory, scope);
            testSHA1     (factory, scope);
            testSHA2_224 (factory, scope);
            testSHA2_256 (factory, scope);
            testSHA2_384 (factory, scope);
            testSHA2_512 (factory, scope);
            testSHA3_224 (factory, scope);
            testSHA3_256 (factory, scope);
            testSHA3_384 (factory, scope);
            testSHA3_512 (factory, scope);

            ////////////////////////////////////////////////////////////////////
            // Алгоритмы вычисления имитовставки
            ////////////////////////////////////////////////////////////////////
            testHMAC_MD5      (factory, scope); 
            testHMAC_RIPEMD128(factory, scope); 
            testHMAC_RIPEMD160(factory, scope); 
            testHMAC_SHA1     (factory, scope); 
            testHMAC_SHA2_224 (factory, scope); 
            testHMAC_SHA2_256 (factory, scope); 
            testHMAC_SHA2_384 (factory, scope); 
            testHMAC_SHA2_512 (factory, scope); 
            testCBCMAC_DES    (factory, scope, 8); 
            testCBCMAC_DES    (factory, scope, 4); 
            testCMAC_AES      (factory, scope); 

            ////////////////////////////////////////////////////////////////////
            // Алгоритмы шифрования
            ////////////////////////////////////////////////////////////////////
            testSkipjack(factory, scope); 
            testRC2     (factory, scope); 
            testRC4     (factory, scope); 
            testRC5     (factory, scope); 
            testDES     (factory, scope); 
            testTDES    (factory, scope); 
            testAES     (factory, scope); 
            
            ////////////////////////////////////////////////////////////////////
            // Алгоритмы наследования ключа
            ////////////////////////////////////////////////////////////////////
            testPBKDF2_HMAC_SHA1(factory, scope); 
            testX942KDF_SHA1    (factory, scope); 

            ////////////////////////////////////////////////////////////////////
            // Алгоритмы шифрования ключа
            ////////////////////////////////////////////////////////////////////
            testWrapSMIME_DES (factory, scope);
            testWrapSMIME_TDES(factory, scope);
            testWrapRC2       (factory, scope); 
            testWrapTDES      (factory, scope); 
            testWrapAES       (factory, scope); 
    
            // указать генератор случайных данных
            try (IRand rand = new aladdin.capi.Rand(null))
            {
                ////////////////////////////////////////////////////////////////////
                // RSA
                ////////////////////////////////////////////////////////////////////
                int[] keySizes = KeySizes.range(1, 32); 

                testRSA(factory, scope, rand, true, KeyFlags.NONE,  384, keySizes); 
                testRSA(factory, scope, rand, true, KeyFlags.NONE,  512, keySizes); 
                testRSA(factory, scope, rand, true, KeyFlags.NONE, 1024, keySizes); 
                testRSA(factory, scope, rand, true, KeyFlags.NONE, 1536, keySizes); 
                testRSA(factory, scope, rand, true, KeyFlags.NONE, 2048, keySizes); 

                ////////////////////////////////////////////////////////////////////
                // DSA/DH
                ////////////////////////////////////////////////////////////////////
                testDSA(factory, scope, rand, true, KeyFlags.NONE); 
                testDH (factory, scope, rand, true, KeyFlags.NONE); 

                ////////////////////////////////////////////////////////////////////
                // ECDSA/ECDH
                ////////////////////////////////////////////////////////////////////
                testECDSA(factory, null); 

                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2PNB163V1   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2PNB163V2   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2PNB163V3   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2PNB176W1   ); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2TNB191V1   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2TNB191V2   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2TNB191V3   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2ONB191V4   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2ONB191V5   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2PNB208W1   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2TNB239V1   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2TNB239V2   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2TNB239V3   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2ONB239V4   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2PNB272W1   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2PNB304W1   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2TNB359V1   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2PNB368W1   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2TNB431R1   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_PRIME192V1   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_PRIME192V2   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_PRIME192V3   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_PRIME239V1   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_PRIME239V2   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_PRIME239V3   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_PRIME256V1   );
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT163K1); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT163R1); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT239K1);
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT113R1);
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT113R2);
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECP112R1);
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECP112R2);
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECP160R1);
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECP160K1);
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECP256K1); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT163R2); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT283K1); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT283R1); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT131R1);
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT131R2);
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT193R1);
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT193R2);
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT233K1); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT233R1); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECP128R1);
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECP128R2);
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECP160R2);
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECP192K1); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECP224K1); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECP224R1); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECP384R1); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECP521R1); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT409K1); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT409R1); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT571K1); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.CERTICOM_CURVES_SECT571R1); 
                testEC(factory, scope, rand, true, KeyFlags.NONE, OID.X962_CURVES_C2ONB239V5   ); 
            }
        }
        catch (Throwable e) { e.printStackTrace(System.err); throw e; }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование хэш-алгоритмов
    ////////////////////////////////////////////////////////////////////////////
    public static void testMD2(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.MD2");
        
        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD2), Null.INSTANCE
        );
        // создать алгоритм
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class))
        {
            // протестировать алгоритм
            aladdin.capi.ansi.hash.MD2.test(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    public static void testMD4(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.MD4");
        
        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD4), Null.INSTANCE
        );
        // создать алгоритм
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class))
        {
            // протестировать алгоритм
            aladdin.capi.ansi.hash.MD4.test(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    public static void testMD5(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.MD5");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD5), Null.INSTANCE
        );
        // создать алгоритм
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class))
        {
            // протестировать алгоритм
            aladdin.capi.ansi.hash.MD5.test(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    public static void testRIPEMD128(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.RIPEMD128");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_RIPEMD128), Null.INSTANCE
        );
        // создать алгоритм
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class))
        {   
            // протестировать алгоритм
            aladdin.capi.ansi.hash.RIPEMD128.test(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    public static void testRIPEMD160(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.RIPEMD160");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_RIPEMD160), Null.INSTANCE
        );
        // создать алгоритм
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class))
        {
            // протестировать алгоритм
            aladdin.capi.ansi.hash.RIPEMD160.test(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    public static void testRIPEMD256(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.RIPEMD256");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_RIPEMD256), Null.INSTANCE
        );
        // создать алгоритм
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class))
        {
            // протестировать алгоритм
            aladdin.capi.ansi.hash.RIPEMD256.test(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    public static void testSHA1(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.SHA1");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
        );
        // создать алгоритм
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class))
        {
            // протестировать алгоритм
            aladdin.capi.ansi.hash.SHA1.test(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    public static void testSHA2_224(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.SHA2_224");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), Null.INSTANCE
        );
        // создать алгоритм
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class))
        {
            // протестировать алгоритм
            aladdin.capi.ansi.hash.SHA2_224.test(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    public static void testSHA2_256(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.SHA2_256");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), Null.INSTANCE
        );
        // создать алгоритм
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class))
        {
            // протестировать алгоритм
            aladdin.capi.ansi.hash.SHA2_256.test(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    public static void testSHA2_384(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.SHA2_384");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), Null.INSTANCE
        );
        // создать алгоритм
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class))
        {
            // протестировать алгоритм
            aladdin.capi.ansi.hash.SHA2_384.test(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    public static void testSHA2_512(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.SHA2_512");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), Null.INSTANCE
        );
        // создать алгоритм
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class))
        {
            // протестировать алгоритм
            aladdin.capi.ansi.hash.SHA2_512.test(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    public static void testSHA3_224(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.SHA3_224");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_224), Null.INSTANCE
        );
        // создать алгоритм
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class))
        {
            // протестировать алгоритм
            aladdin.capi.ansi.hash.SHA3.test224(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    public static void testSHA3_256(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.SHA3_256");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_256), Null.INSTANCE
        );
        // создать алгоритм
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class))
        {
            // протестировать алгоритм
            aladdin.capi.ansi.hash.SHA3.test256(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    public static void testSHA3_384(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.SHA3_384");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_384), Null.INSTANCE
        );
        // создать алгоритм
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class))
        {
            // протестировать алгоритм
            aladdin.capi.ansi.hash.SHA3.test384(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    public static void testSHA3_512(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.SHA3_512");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_512), Null.INSTANCE
        );
        // создать алгоритм
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class))
        {
            // протестировать алгоритм
            aladdin.capi.ansi.hash.SHA3.test512(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование алгоритмов вычисления имитовставки
    ////////////////////////////////////////////////////////////////////////////
    public static void testHMAC_MD5(Factory factory, SecurityStore scope) throws Exception
    {
        println("MAC.HMAC_MD5");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.IPSEC_HMAC_MD5), Null.INSTANCE
        ); 
        // создать алгоритм 
        try (Mac algorithm = (Mac)factory.createAlgorithm(scope, parameters, Mac.class))
        {
            // выполнить тест
            aladdin.capi.ansi.hash.MD5.testHMAC(algorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // указать допустимые размеры
                int[] dataSizes = new int[] { 0, 1, 63, 64, 65 }; 
                
                // выполнить тест
                macTest(algorithm, trustFactory, null, parameters, dataSizes); 
            }
        }
    }
    public static void testHMAC_RIPEMD128(Factory factory, SecurityStore scope) throws Exception
    {
        println("MAC.HMAC_RIPEMD128");

        // указать параметры алгоритма
        AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_RIPEMD128), Null.INSTANCE
        ); 
        // получить алгоритм хэширования
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
            scope, hashParameters, Hash.class))
        {
            // проверить наличие алгоритма хэширования
            if (hashAlgorithm == null) return; 

            // создать алгоритм
            try (Mac algorithm = new aladdin.capi.mac.HMAC(hashAlgorithm))
            {
                // выполнить тест
                aladdin.capi.ansi.hash.RIPEMD128.testHMAC(algorithm);
            }
        }
    }
    public static void testHMAC_RIPEMD160(Factory factory, SecurityStore scope) throws Exception
    {
        println("MAC.HMAC_RIPEMD160");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.IPSEC_HMAC_RIPEMD160), Null.INSTANCE
        ); 
        // создать алгоритм 
        try (Mac algorithm = (Mac)factory.createAlgorithm(scope, parameters, Mac.class))
        {
            // выполнить тест
            aladdin.capi.ansi.hash.RIPEMD160.testHMAC(algorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // указать допустимые размеры
                int[] dataSizes = new int[] { 0, 1, 63, 64, 65 }; 
                
                // выполнить тест
                macTest(algorithm, trustFactory, null, parameters, dataSizes); 
            }
        }
    }
    public static void testHMAC_SHA1(Factory factory, SecurityStore scope) throws Exception
    {
        println("MAC.HMAC_SHA1");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_HMAC_SHA1), Null.INSTANCE
        ); 
        // создать алгоритм 
        try (Mac algorithm = (Mac)factory.createAlgorithm(scope, parameters, Mac.class))
        {
            // выполнить тест
            aladdin.capi.ansi.hash.SHA1.testHMAC(algorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // указать допустимые размеры
                int[] dataSizes = new int[] { 0, 1, 63, 64, 65 }; 
                
                // выполнить тест
                macTest(algorithm, trustFactory, null, parameters, dataSizes); 
            }
        }
    }
    public static void testHMAC_SHA2_224(Factory factory, SecurityStore scope) throws Exception
    {
        println("MAC.HMAC_SHA2_224");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_224), Null.INSTANCE
        ); 
        // создать алгоритм 
        try (Mac algorithm = (Mac)factory.createAlgorithm(scope, parameters, Mac.class))
        {
            // выполнить тест
            aladdin.capi.ansi.hash.SHA2_224.testHMAC(algorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // указать допустимые размеры
                int[] dataSizes = new int[] { 0, 1, 63, 64, 65 }; 
                
                // выполнить тест
                macTest(algorithm, trustFactory, null, parameters, dataSizes); 
            }
        }
    }
    public static void testHMAC_SHA2_256(Factory factory, SecurityStore scope) throws Exception
    {
        println("MAC.HMAC_SHA2_256");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_256), Null.INSTANCE
        ); 
        // создать алгоритм 
        try (Mac algorithm = (Mac)factory.createAlgorithm(scope, parameters, Mac.class))
        {
            // выполнить тест
            aladdin.capi.ansi.hash.SHA2_256.testHMAC(algorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // указать допустимые размеры
                int[] dataSizes = new int[] { 0, 1, 63, 64, 65 }; 
                
                // выполнить тест
                macTest(algorithm, trustFactory, null, parameters, dataSizes); 
            }
        }
    }
    public static void testHMAC_SHA2_384(Factory factory, SecurityStore scope) throws Exception
    {
        println("MAC.HMAC_SHA2_384");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_384), Null.INSTANCE
        ); 
        // создать алгоритм 
        try (Mac algorithm = (Mac)factory.createAlgorithm(scope, parameters, Mac.class))
        {
            // выполнить тест
            aladdin.capi.ansi.hash.SHA2_384.testHMAC(algorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // указать допустимые размеры
                int[] dataSizes = new int[] { 0, 1, 127, 128, 129 }; 
                
                // выполнить тест
                macTest(algorithm, trustFactory, null, parameters, dataSizes); 
            }
        }
    }
    public static void testHMAC_SHA2_512(Factory factory, SecurityStore scope) throws Exception
    {
        println("MAC.HMAC_SHA2_512");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_512), Null.INSTANCE
        ); 
        // создать алгоритм 
        try (Mac algorithm = (Mac)factory.createAlgorithm(scope, parameters, Mac.class))
        {
            // выполнить тест
            aladdin.capi.ansi.hash.SHA2_512.testHMAC(algorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // указать допустимые размеры
                int[] dataSizes = new int[] { 0, 1, 127, 128, 129 }; 
                
                // выполнить тест
                macTest(algorithm, trustFactory, null, parameters, dataSizes); 
            }
        }
    }
    public static void testCBCMAC_DES(Factory factory, 
        SecurityStore scope, int macSize) throws Exception
    {
        println("MAC.CBCMAC_DES"); 
        
        // указать параметры алгоритма
	    AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_MAC),
            new Integer(macSize * 8)
        ); 
        // создать алгоритм выработки имитовставки
        try (Mac algorithm = (Mac)factory.createAlgorithm(scope, parameters, Mac.class))
        {
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // указать допустимые размеры
                int[] dataSizes = new int[] { 0, 8, 16 }; 
                
                // выполнить тест
                macTest(algorithm, trustFactory, null, parameters, dataSizes); 
            }
        }
    }
    public static void testCMAC_AES(Factory factory, SecurityStore scope) throws Exception
    {
        println("MAC.CMAC_AES");

        // создать блочный алгоритм шифрования
        try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
            scope, "AES", Null.INSTANCE, IBlockCipher.class))
        {
            // создать алгоритм выработки имитовставки
            try (Mac algorithm = aladdin.capi.mac.OMAC1.create(blockCipher, new byte[16], 16))
            {
                // протестировать алгоритм
                aladdin.capi.ansi.engine.AES.test128_CMAC(algorithm);
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование алгоритмов шифрования
    ////////////////////////////////////////////////////////////////////////////
    public static void testSkipjack(Factory factory, SecurityStore scope) throws Exception
    {
        println("Cipher.Skipjack");

		// указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.INFOSEC_SKIPJACK_CBC), 
            new aladdin.asn1.ansi.SkipjackParm(new OctetString(new byte[8]))
        ); 
        // создать алгоритм шифрования
        try (Cipher cipher = (Cipher)factory.createAlgorithm(
            scope, parameters, Cipher.class))
        {
            // выполнить тест
            aladdin.capi.ansi.engine.Skipjack.test(cipher); 
        }
    }
    public static void testRC2(Factory factory, SecurityStore scope) throws Exception
    {
        println("Cipher.RC2");

        // указать идентификатор алгоритма
        ObjectIdentifier oid = new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_RC2_ECB);
        
        // закодировать параметры алгоритма
        IEncodable engineParameters = aladdin.asn1.ansi.rsa.RC2ParameterVersion.getVersion(63);  
        
        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(oid, engineParameters); 
            
        // создать алгоритм шифрования
        try (Cipher engine = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        {
            // выполнить тест
            if (engine != null) aladdin.capi.ansi.engine.RC2.test63(engine); 
            
            // указать доверенную фабрику
            if (engine != null) try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // выполнить тест
                cipherTest(engine, trustFactory, null, parameters); 
            }
        }
        // закодировать параметры алгоритма
        engineParameters = aladdin.asn1.ansi.rsa.RC2ParameterVersion.getVersion(64);  
        
        // указать параметры алгоритма
        parameters = new AlgorithmIdentifier(oid, engineParameters); 
            
        // создать алгоритм шифрования
        try (Cipher engine = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        {
            // выполнить тест
            if (engine != null) aladdin.capi.ansi.engine.RC2.test64(engine); 

            // указать доверенную фабрику
            if (engine != null) try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // выполнить тест
                cipherTest(engine, trustFactory, null, parameters); 
            }
        }
        // закодировать параметры алгоритма
        engineParameters = aladdin.asn1.ansi.rsa.RC2ParameterVersion.getVersion(128);  
        
        // указать параметры алгоритма
        parameters = new AlgorithmIdentifier(oid, engineParameters); 
            
        // создать алгоритм шифрования
        try (Cipher engine = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        {
            // выполнить тест
            if (engine != null) aladdin.capi.ansi.engine.RC2.test128(engine); 

            // указать доверенную фабрику
            if (engine != null) try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // выполнить тест
                cipherTest(engine, trustFactory, null, parameters); 
            }
        }
        // закодировать параметры алгоритма
        engineParameters = aladdin.asn1.ansi.rsa.RC2ParameterVersion.getVersion(129);  
        
        // указать параметры алгоритма
        parameters = new AlgorithmIdentifier(oid, engineParameters); 
            
        // создать алгоритм шифрования
        try (Cipher engine = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        {
            // выполнить тест
            if (engine != null) aladdin.capi.ansi.engine.RC2.test129(engine); 
            
            // указать доверенную фабрику
            if (engine != null) try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // выполнить тест
                cipherTest(engine, trustFactory, null, parameters); 
            }
        }
    }
    public static void testRC4(Factory factory, SecurityStore scope) throws Exception
    {
        println("Cipher.RC4");

        // указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_RC4), Null.INSTANCE
        ); 
        // создать алгоритм шифрования
        try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        {
            // выполнить тест
            aladdin.capi.ansi.cipher.RC4.test(cipher);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // указать допустимые размеры
                int[] dataSizes = new int[] { 0, 1, 63, 64, 65, 127, 128, 129 }; 
                
                // выполнить тест
                cipherTest(cipher, PaddingMode.NONE, trustFactory, null, parameters, dataSizes); 
            }
        }
    }
    public static void testRC5(Factory factory, SecurityStore scope) throws Exception
    {
        println("Cipher.RC5");

        // указать тестируемое число раундов
        int[] rounds = new int[] { 0, 1, 2, 8, 12, 16 }; 
        
        // сгенерировать случайную синхропосылку
        byte[] iv = new byte[8]; generate(iv, 0, iv.length); 
        
        // для всех тестируемых раундов
        for (int i = 0; i < rounds.length; i++)
        {
            // закодировать параметры алгоритма
            IEncodable cipherParameters = new aladdin.asn1.ansi.rsa.RC5CBCParameter(
    			new Integer(16), new Integer(rounds[i]), new Integer(64), new OctetString(iv)
            ); 
            // указать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_RC5_CBC), cipherParameters
            ); 
            // создать алгоритм шифрования
            try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
            {
                // проверить наличие алгоритма
                if (cipher == null) continue; 
                
                // указать доверенную фабрику
                try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
                { 
                    // выполнить тест
                    cipherTest(cipher, trustFactory, null, parameters); 
                }
            }
            // создать блочный алгоритм шифрования
            try (IBlockCipher blockCipher = 
                new aladdin.capi.ansi.cipher.RC5(factory, scope, 8, rounds[i]))
            {
                switch (rounds[i])
                { 
                case  0: aladdin.capi.ansi.engine.RC5_64.test0 (blockCipher); break; 
                case  1: aladdin.capi.ansi.engine.RC5_64.test1 (blockCipher); break; 
                case  2: aladdin.capi.ansi.engine.RC5_64.test2 (blockCipher); break; 
                case  8: aladdin.capi.ansi.engine.RC5_64.test8 (blockCipher); break; 
                case 12: aladdin.capi.ansi.engine.RC5_64.test12(blockCipher); break; 
                case 16: aladdin.capi.ansi.engine.RC5_64.test16(blockCipher); break; 
                }
            }
            // указать параметры алгоритма
            parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_RC5_CBC_PAD), cipherParameters
            ); 
            // создать алгоритм шифрования
            try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
            {
                // проверить наличие алгоритма
                if (cipher == null) continue; 
                
                // указать доверенную фабрику
                try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
                { 
                    // указать допустимые размеры
                    int[] dataSizes = new int[] { 0, 1, 7, 8, 9, 15, 16, 17 }; 
                    
                    // выполнить тест
                    cipherTest(cipher, PaddingMode.ANY, 
                        trustFactory, null, parameters, dataSizes
                    ); 
                }
            }
        }
    }
    public static void testDES(Factory factory, SecurityStore scope) throws Exception
    {
        println("Cipher.DES");

        // указать параметры алгоритма
	    AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_ECB), Null.INSTANCE
        ); 
        // создать алгоритм шифрования
        try (Cipher engine = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        {
            // выполнить тест
            aladdin.capi.ansi.engine.DES.test(engine);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // выполнить тест
                cipherTest(engine, trustFactory, null, parameters); 
            }
        }
    }
    public static void testTDES(Factory factory, SecurityStore scope) throws Exception
    {
        println("Cipher.TDES");

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_TDES_ECB), Null.INSTANCE); 
        
        // создать алгоритм шифрования
        try (Cipher engine = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        {
            // выполнить тест
            aladdin.capi.ansi.engine.TDES.test(engine);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // выполнить тест
                cipherTest(engine, trustFactory, null, parameters); 
            }
        }
    }
    public static void testAES(Factory factory, SecurityStore scope) throws Exception
    {
        println("Cipher.AES");

        // указать параметры алгоритма
	    AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES128_ECB), Null.INSTANCE
        ); 
        // создать алгоритм шифрования
        try (Cipher engine = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        {
            // выполнить тест
            if (engine != null) aladdin.capi.ansi.engine.AES.test128(engine);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // выполнить тест
                cipherTest(engine, trustFactory, null, parameters); 
            }
        }
	    // указать параметры алгоритма
	    parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_ECB), Null.INSTANCE
        ); 
        // создать алгоритм шифрования
        try (Cipher engine = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        {
            // выполнить тест
            if (engine != null) aladdin.capi.ansi.engine.AES.test192(engine);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // выполнить тест
                cipherTest(engine, trustFactory, null, parameters); 
            }
        }
	    // указать параметры алгоритма
	    parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES256_ECB), Null.INSTANCE
        ); 
        // создать алгоритм шифрования
        try (Cipher engine = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        {
            // выполнить тест
            if (engine != null) aladdin.capi.ansi.engine.AES.test256(engine);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
            { 
                // выполнить тест
                cipherTest(engine, trustFactory, null, parameters); 
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование алгоритмов наследования ключа
    ////////////////////////////////////////////////////////////////////////////
    public static void testPBKDF2_HMAC_SHA1(Factory factory, SecurityStore scope) throws Exception
    {
        println("KeyDerive.PBKDF2_HMAC_SHA1");
        
        // выполнить тест
        aladdin.capi.ansi.hash.SHA1.testHMAC_PBKDF2(factory, scope); 
    }
    public static void testX942KDF_SHA1(Factory factory, SecurityStore scope) throws Exception
    {
        println("KeyDerive.X942KDF_SHA1");

        // закодировать параметры алгоритма хэширования
		AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
			new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
        ); 
        // создать алгоритм хэширования
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class)) 
        {
            // выполнить тест
            if (hashAlgorithm != null) aladdin.capi.ansi.derive.X942KDF.testSHA1(hashAlgorithm);
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование алгоритмов шифрования ключа
    ////////////////////////////////////////////////////////////////////////////
    public static void testWrapSMIME_DES(Factory factory, SecurityStore scope) throws Exception
    {
        println("KeyWrap.SMIME_DES");

        // указать алгоритм шифрования
        try (IBlockCipher des = (IBlockCipher)factory.createAlgorithm(
            scope, "DES", Null.INSTANCE, IBlockCipher.class))
        {
            // выполнить тест
            aladdin.capi.ansi.engine.DES.testSMIME(des);
        }
    }
    public static void testWrapSMIME_TDES(Factory factory, SecurityStore scope) throws Exception
    {
        println("KeyWrap.SMIME_TDES");

        // указать алгоритм шифрования
        try (IBlockCipher tdes = (IBlockCipher)factory.createAlgorithm(
            scope, "DESede", Null.INSTANCE, IBlockCipher.class))
        {
            // выполнить тест
            aladdin.capi.ansi.engine.TDES.testSMIME(tdes);
        }
    }
    public static void testWrapRC2(Factory factory, SecurityStore scope) throws Exception
    {
        println("KeyWrap.RC2");

        // указать идентификатор алгоритма
        ObjectIdentifier oid = new ObjectIdentifier(
            aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_RC2_128_WRAP
        ); 
        // указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            oid, aladdin.asn1.ansi.rsa.RC2ParameterVersion.getVersion(40)
        );
        // создать алгоритм
        try (KeyWrap algorithm = (KeyWrap)factory.createAlgorithm(
            scope, parameters, KeyWrap.class))
        {
            // выполнить тест
            if (algorithm != null) aladdin.capi.ansi.wrap.RC2.test40(algorithm);
        }
        // указать параметры алгоритма
		parameters = new AlgorithmIdentifier(
            oid, aladdin.asn1.ansi.rsa.RC2ParameterVersion.getVersion(128)
        );
        // создать алгоритм
        try (KeyWrap algorithm = (KeyWrap)factory.createAlgorithm(
            scope, parameters, KeyWrap.class))
        {
            // выполнить тест
            if (algorithm != null) aladdin.capi.ansi.wrap.RC2.test128(algorithm);
        }
    }
    public static void testWrapTDES(Factory factory, SecurityStore scope) throws Exception
    {
        println("KeyWrap.TDES");

        // указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_TDES192_WRAP), 
            Null.INSTANCE
        );
        // создать алгоритм
        try (KeyWrap algorithm = (KeyWrap)factory.createAlgorithm(
            scope, parameters, KeyWrap.class))
        {
            // выполнить тест
            aladdin.capi.ansi.wrap.TDES.test(algorithm); 
        }
    }
    public static void testWrapAES(Factory factory, SecurityStore scope) throws Exception
    {
        println("KeyWrap.AES");

        // указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES128_WRAP), Null.INSTANCE
        );
        // создать алгоритм
        try (KeyWrap algorithm = (KeyWrap)factory.createAlgorithm(
            scope, parameters, KeyWrap.class))
        {
            // выполнить тест
            if (algorithm != null) aladdin.capi.ansi.wrap.AES.test(algorithm);
        }
        // указать параметры алгоритма
		parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES128_WRAP_PAD), Null.INSTANCE
        );
        // создать алгоритм
        try (KeyWrap algorithm = (KeyWrap)factory.createAlgorithm(
            scope, parameters, KeyWrap.class))
        {
            // выполнить тест
            if (algorithm != null) aladdin.capi.ansi.wrap.AES_PAD.test(algorithm);
        }
        // указать параметры алгоритма
		parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_WRAP), Null.INSTANCE
        );
        // создать алгоритм
        try (KeyWrap algorithm = (KeyWrap)factory.createAlgorithm(
            scope, parameters, KeyWrap.class))
        {
            // выполнить тест
            if (algorithm != null) aladdin.capi.ansi.wrap.AES.test(algorithm);
        }
        // указать параметры алгоритма
		parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_WRAP_PAD), Null.INSTANCE
        );
        // создать алгоритм
        try (KeyWrap algorithm = (KeyWrap)factory.createAlgorithm(
            scope, parameters, KeyWrap.class))
        {
            // выполнить тест
            if (algorithm != null) aladdin.capi.ansi.wrap.AES_PAD.test(algorithm);
        }
        // указать параметры алгоритма
		parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES256_WRAP), Null.INSTANCE
        );
        // создать алгоритм
        try (KeyWrap algorithm = (KeyWrap)factory.createAlgorithm(
            scope, parameters, KeyWrap.class))
        {
            // выполнить тест
            if (algorithm != null) aladdin.capi.ansi.wrap.AES.test(algorithm);
        }
        // указать параметры алгоритма
		parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES256_WRAP_PAD), Null.INSTANCE
        );
        // создать алгоритм
        try (KeyWrap algorithm = (KeyWrap)factory.createAlgorithm(
            scope, parameters, KeyWrap.class))
        {
            // выполнить тест
            if (algorithm != null) aladdin.capi.ansi.wrap.AES_PAD.test(algorithm);
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование RSA
    ////////////////////////////////////////////////////////////////////////////
    public static void testRSA(Factory factory, SecurityObject scope, IRand rand, 
        boolean generate, KeyFlags keyFlags, int bits, int[] keySizes) throws Exception
    {
        println("RSA/%1$s", bits);

        // указать идентификатор ключа
        String keyOID = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA; 
        
        // указать доверенную фабрику
        try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
        { 
            // получить фабрику кодирования ключей
            KeyFactory keyFactory = trustFactory.getKeyFactory(keyOID); 
            
            // указать способ использования ключа
            KeyUsage keyUsage = keyFactory.getKeyUsage(); 
        
            // указать параметры ключа
            IParameters parameters = new aladdin.capi.ansi.rsa.Parameters(bits); 
            
            // сгенерировать ключевую пару
            try (KeyPair keyPair = generateKeyPair(
                factory, scope, rand, trustFactory, null, generate, 
                keyOID, parameters, keyUsage, keyFlags)) 
            {
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.DIGITAL_SIGNATURE))
                { 
                    // выполнить тесты
                    testSignRSA(trustFactory, null, keyPair, keyFlags); 
                }
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.DATA_ENCIPHERMENT) || 
                    keyUsage.contains(KeyUsage.KEY_ENCIPHERMENT))
                { 
                    // выполнить тесты
                    testKeyxRSA(trustFactory, null, keyPair, keyFlags, keySizes); 
                }
            }
            // удалить ключи контейнера
            finally { deleteKeys(scope); }
        }
        println();
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование подписи RSA
    ////////////////////////////////////////////////////////////////////////////
    private static boolean hashSupportedRSA_PKCS1(
        IPublicKey publicKey, AlgorithmIdentifier hashParameters, int hashSize)
    {
        // преобразовать тип ключа
        aladdin.capi.ansi.rsa.IPublicKey rsaPublicKey = 
            (aladdin.capi.ansi.rsa.IPublicKey)publicKey; 

        // определить размер модуля в байтах
        int k = (rsaPublicKey.getModulus().bitLength() + 7) / 8; 

        // закодировать хэш-значение 
        aladdin.asn1.iso.pkcs.DigestInfo digestInfo = 
            new aladdin.asn1.iso.pkcs.DigestInfo(
                hashParameters, new OctetString(new byte[hashSize])
        ); 
        // проверить размер хэш-значения
        return (digestInfo.encoded().length <= k - 11);
    }  
    // поддержка подписи хэш-значения
    private static boolean hashSupportedRSA_PSS(
        IPublicKey publicKey, int hashSize, int saltLength)
    {
        // преобразовать тип ключа
        aladdin.capi.ansi.rsa.IPublicKey rsaPublicKey = 
            (aladdin.capi.ansi.rsa.IPublicKey)publicKey; 

        // определить размер модуля в байтах
        int emLen = (rsaPublicKey.getModulus().bitLength() - 1 + 7) / 8; 
        
        // определить размер хэш-значения и salt-значения
        return emLen >= saltLength + hashSize + 2; 
    }
    public static void testSignRSA(Factory factory, SecurityStore scope,
        KeyPair keyPair, KeyFlags keyFlags) throws Exception
    {
        // закодировать параметры алгоритма подписи
        AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
        );
        // закодировать параметры алгоритма хэширования
        AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD2), Null.INSTANCE
        );
        // указать параметры алгоритма подписи данных
        AlgorithmIdentifier signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_RSA_MD2), null
        );
        // получить алгоритм подписи данных
        try (SignData signAlgorithm = (SignData)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignData.class)) 
        {
            // при поддержке алгоритма
            if (signAlgorithm != null && hashSupportedRSA_PKCS1(
                keyPair.publicKey, hashParameters, 16)) 
            {
                // выполнить тест
                signTest(factory, scope, hashParameters, 
                    signHashParameters, signParameters, keyPair, keyFlags
                ); 
            }
            // при поддержке алгоритма
            if (signAlgorithm != null && hashSupportedRSA_PSS(keyPair.publicKey, 16, 20)) 
            {
                // выполнить тест
                testSignRSA_PSS(factory, scope,  
                    keyPair, keyFlags, hashParameters, 20
                ); 
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD4), Null.INSTANCE
        );
        // указать параметры алгоритма подписи данных
        signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_RSA_MD4), null
        );
        // получить алгоритм подписи данных
        try (SignData signAlgorithm = (SignData)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignData.class)) 
        {
            // при поддержке алгоритма
            if (signAlgorithm != null && hashSupportedRSA_PKCS1(
                keyPair.publicKey, hashParameters, 16)) 
            {
                // выполнить тест
                signTest(factory, scope, hashParameters, 
                    signHashParameters, signParameters, keyPair, keyFlags
                ); 
            }
            // при поддержке алгоритма
            if (signAlgorithm != null && hashSupportedRSA_PSS(keyPair.publicKey, 16, 20)) 
            {
                // выполнить тест
                testSignRSA_PSS(factory, scope,  
                    keyPair, keyFlags, hashParameters, 20
                ); 
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD5), Null.INSTANCE
        );
        // указать параметры алгоритма подписи данных
        signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_RSA_MD5), null
        );
        // получить алгоритм подписи данных
        try (SignData signAlgorithm = (SignData)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignData.class)) 
        {
            // при поддержке алгоритма хэширования
            if (signAlgorithm != null && hashSupportedRSA_PKCS1(
                keyPair.publicKey, hashParameters, 16)) 
            {
                // выполнить тест
                signTest(factory, scope, hashParameters, 
                    signHashParameters, signParameters, keyPair, keyFlags
                ); 
            }
            // при поддержке алгоритма
            if (signAlgorithm != null && hashSupportedRSA_PSS(keyPair.publicKey, 16, 20)) 
            {
                // выполнить тест
                testSignRSA_PSS(factory, scope,  
                    keyPair, keyFlags, hashParameters, 20
                ); 
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
        );
        // указать параметры алгоритма подписи данных
        signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1), null
        );
        // получить алгоритм подписи данных
        try (SignData signAlgorithm = (SignData)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignData.class)) 
        {
            // при поддержке алгоритма хэширования
            if (signAlgorithm != null && hashSupportedRSA_PKCS1(
                keyPair.publicKey, hashParameters, 20)) 
            {
                // выполнить тест
                signTest(factory, scope, hashParameters, 
                    signHashParameters, signParameters, keyPair, keyFlags
                ); 
            }
            // при поддержке алгоритма
            if (signAlgorithm != null && hashSupportedRSA_PSS(keyPair.publicKey, 20, 20)) 
            {
                // выполнить тест
                testSignRSA_PSS(factory, scope,  
                    keyPair, keyFlags, hashParameters, 20
                ); 
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), Null.INSTANCE
        );
        // указать параметры алгоритма подписи данных
        signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_256), null
        );
        // получить алгоритм подписи данных
        try (SignData signAlgorithm = (SignData)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignData.class)) 
        {
            // при поддержке алгоритма хэширования
            if (signAlgorithm != null && hashSupportedRSA_PKCS1(
                keyPair.publicKey, hashParameters, 32)) 
            {
                // выполнить тест
                signTest(factory, scope, hashParameters, 
                    signHashParameters, signParameters, keyPair, keyFlags
                ); 
            }
            // при поддержке алгоритма
            if (signAlgorithm != null && hashSupportedRSA_PSS(keyPair.publicKey, 32, 20)) 
            {
                // выполнить тест
                testSignRSA_PSS(factory, scope,  
                    keyPair, keyFlags, hashParameters, 20
                ); 
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), Null.INSTANCE
        );
        // указать параметры алгоритма подписи данных
        signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_384), null
        );
        // получить алгоритм подписи данных
        try (SignData signAlgorithm = (SignData)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignData.class)) 
        {
            // при поддержке алгоритма хэширования
            if (signAlgorithm != null && hashSupportedRSA_PKCS1(
                keyPair.publicKey, hashParameters, 48)) 
            {
                // выполнить тест
                signTest(factory, scope, hashParameters, 
                    signHashParameters, signParameters, keyPair, keyFlags
                ); 
            }
            // при поддержке алгоритма
            if (signAlgorithm != null && hashSupportedRSA_PSS(keyPair.publicKey, 48, 20)) 
            {
                // выполнить тест
                testSignRSA_PSS(factory, scope, 
                    keyPair, keyFlags, hashParameters, 20
                ); 
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), Null.INSTANCE
        );
        // указать параметры алгоритма подписи данных
        signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_512), null
        );
        // получить алгоритм подписи данных
        try (SignData signAlgorithm = (SignData)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignData.class)) 
        {
            // при поддержке алгоритма хэширования
            if (signAlgorithm != null && hashSupportedRSA_PKCS1(
                keyPair.publicKey, hashParameters, 64)) 
            {
                // выполнить тест
                signTest(factory, scope, hashParameters, 
                    signHashParameters, signParameters, keyPair, keyFlags
                ); 
            }
            // при поддержке алгоритма
            if (signAlgorithm != null && hashSupportedRSA_PSS(keyPair.publicKey, 64, 20)) 
            {
                // выполнить тест
                testSignRSA_PSS(factory, scope,  
                    keyPair, keyFlags, hashParameters, 20
                ); 
            }
        }
    }
    private static void testSignRSA_PSS(Factory factory, 
        SecurityStore scope, KeyPair keyPair, KeyFlags keyFlags, 
        AlgorithmIdentifier hashParameters, int saltLength) throws Exception
    {
        // закодировать параметры алгоритма генерации маски
        AlgorithmIdentifier maskParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MGF1), hashParameters
        ); 
        // закодировать параметры алгоритма подписи
        AlgorithmIdentifier signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS), 
            new aladdin.asn1.iso.pkcs.pkcs1.RSASSAPSSParams(
                hashParameters, maskParameters, new Integer(saltLength), new Integer(1)
            )
        ); 
        // получить алгоритм выработки подписи
        try (IAlgorithm signHash = keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignHash.class)) 
        {
            // проверить поддержку алгоритма
            if (signHash == null) return; 
        }
        // выполнить тест
        signTest(factory, scope, hashParameters, 
            signParameters, signParameters, keyPair, keyFlags
        ); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование шифрования и обмена ключами RSA
    ////////////////////////////////////////////////////////////////////////////
    private static int maxDataSizeRSA_PKCS1(IPublicKey publicKey)
    {
        // преобразовать тип ключа
        aladdin.capi.ansi.rsa.IPublicKey rsaPublicKey = 
            (aladdin.capi.ansi.rsa.IPublicKey)publicKey; 

        // вычислить максимальный размер данных
        return (rsaPublicKey.getModulus().bitLength() + 7) / 8 - 11; 
    }
    private static int maxDataSizeRSA_OAEP(IPublicKey publicKey, int hashSize)
    {
        // преобразовать тип ключа
        aladdin.capi.ansi.rsa.IPublicKey rsaPublicKey = 
            (aladdin.capi.ansi.rsa.IPublicKey)publicKey; 

        // определить размер модуля в байтах
        int k = (rsaPublicKey.getModulus().bitLength() + 7) / 8; 
        
        // вернуть максимальный размер данных
        return k - 2 * hashSize - 2;
    }
    public static void testKeyxRSA(Factory factory, SecurityStore scope,
        KeyPair keyPair, KeyFlags keyFlags, int[] keySizes) throws Exception
    {
        testKeyxRSA_PKCS1(factory, scope, keyPair, keyFlags, keySizes); 
        testKeyxRSA_OAEP (factory, scope, keyPair, keyFlags, keySizes); 
    }
    private static void testKeyxRSA_PKCS1(Factory factory, SecurityStore scope,
        KeyPair keyPair, KeyFlags keyFlags, int[] keySizes) throws Exception
    {
        // закодировать параметры алгоритма 
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
        );
        // вычислить максимальный размер данных
        int dataSize = maxDataSizeRSA_PKCS1(keyPair.publicKey); if (dataSize > 0)
        {        
            // выполнить тест
            ciphermentTest(factory, scope, parameters, keyPair, keyFlags, dataSize, keySizes);
        }
    }
    private static void testKeyxRSA_OAEP(Factory factory, SecurityStore scope,
        KeyPair keyPair, KeyFlags keyFlags, int[] keySizes) throws Exception
    {
        // закодировать параметры алгоритма хэширования
        AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD2), Null.INSTANCE
        );
        // получить алгоритм хэширования
        try (Hash hashAlgorithm = (Hash)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), hashParameters, Hash.class)) 
        {
            // вычислить максимальный размер данных
            int dataSize = maxDataSizeRSA_OAEP(keyPair.publicKey, 16); 
            
            // при поддержке алгоритма
            if (hashAlgorithm != null && dataSize > 0)
            {
                // выполнить тест
                testKeyxRSA_OAEP(factory, scope, keyPair, 
                    keyFlags, hashParameters, dataSize, keySizes
                );
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD4), Null.INSTANCE
        );
        // получить алгоритм хэширования
        try (Hash hashAlgorithm = (Hash)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), hashParameters, Hash.class)) 
        {
            // вычислить максимальный размер данных
            int dataSize = maxDataSizeRSA_OAEP(keyPair.publicKey, 16); 
            
            // при поддержке алгоритма
            if (hashAlgorithm != null && dataSize > 0)
            {
                // выполнить тест
                testKeyxRSA_OAEP(factory, scope, keyPair, 
                    keyFlags, hashParameters, dataSize, keySizes
                );
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD5), Null.INSTANCE
        );
        // получить алгоритм хэширования
        try (Hash hashAlgorithm = (Hash)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), hashParameters, Hash.class)) 
        {
            // вычислить максимальный размер данных
            int dataSize = maxDataSizeRSA_OAEP(keyPair.publicKey, 16); 
            
            // при поддержке алгоритма
            if (hashAlgorithm != null && dataSize > 0)
            {
                // выполнить тест
                testKeyxRSA_OAEP(factory, scope, keyPair, 
                    keyFlags, hashParameters, dataSize, keySizes
                );
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
        );
        // получить алгоритм хэширования
        try (Hash hashAlgorithm = (Hash)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), hashParameters, Hash.class)) 
        {
            // вычислить максимальный размер данных
            int dataSize = maxDataSizeRSA_OAEP(keyPair.publicKey, 20); 
            
            // при поддержке алгоритма
            if (hashAlgorithm != null && dataSize > 0)
            {
                // выполнить тест
                testKeyxRSA_OAEP(factory, scope, keyPair, 
                    keyFlags, hashParameters, dataSize, keySizes
                );
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), Null.INSTANCE
        );
        // получить алгоритм хэширования
        try (Hash hashAlgorithm = (Hash)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), hashParameters, Hash.class)) 
        {
            // вычислить максимальный размер данных
            int dataSize = maxDataSizeRSA_OAEP(keyPair.publicKey, 32); 
            
            // при поддержке алгоритма
            if (hashAlgorithm != null && dataSize > 0)
            {
                // выполнить тест
                testKeyxRSA_OAEP(factory, scope, keyPair, 
                    keyFlags, hashParameters, dataSize, keySizes
                );
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), Null.INSTANCE
        );
        // получить алгоритм хэширования
        try (Hash hashAlgorithm = (Hash)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), hashParameters, Hash.class)) 
        {
            // вычислить максимальный размер данных
            int dataSize = maxDataSizeRSA_OAEP(keyPair.publicKey, 48); 
            
            // при поддержке алгоритма
            if (hashAlgorithm != null && dataSize > 0)
            {
                // выполнить тест
                testKeyxRSA_OAEP(factory, scope, keyPair, 
                    keyFlags, hashParameters, dataSize, keySizes
                );
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), Null.INSTANCE
        );
        // получить алгоритм хэширования
        try (Hash hashAlgorithm = (Hash)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), hashParameters, Hash.class)) 
        {
            // вычислить максимальный размер данных
            int dataSize = maxDataSizeRSA_OAEP(keyPair.publicKey, 64); 
            
            // при поддержке алгоритма
            if (hashAlgorithm != null && dataSize > 0)
            {
                // выполнить тест
                testKeyxRSA_OAEP(factory, scope, keyPair, 
                    keyFlags, hashParameters, dataSize, keySizes
                );
            }
        }
    }
    private static void testKeyxRSA_OAEP(Factory factory, SecurityStore scope,
        KeyPair keyPair, KeyFlags keyFlags, AlgorithmIdentifier hashParameters, 
        int dataSize, int[] keySizes) throws Exception
    {
        // закодировать параметры алгоритма генерации маски
        AlgorithmIdentifier maskParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MGF1), hashParameters
        ); 
        // закодировать параметры алгоритма 
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_OAEP), 
            new aladdin.asn1.iso.pkcs.pkcs1.RSAESOAEPParams(
                hashParameters, maskParameters, null
            )
        ); 
        // получить алгоритм шифрования
        try (IAlgorithm algorithm = keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), parameters, Encipherment.class)) 
        {
            // проверить поддержку алгоритма
            if (algorithm == null) return; 
        }
        // выполнить тест
        ciphermentTest(factory, scope, parameters, keyPair, keyFlags, dataSize, keySizes);
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование DSA
    ////////////////////////////////////////////////////////////////////////////
    private static boolean hashSupportedDSA(IParameters parameters, int hashSize) 
    { 
        // выполнить преобразование типа
        aladdin.capi.ansi.x957.IParameters dsaParameters = 
            (aladdin.capi.ansi.x957.IParameters)parameters; 

        // проверить размер хэш-значения
        return (hashSize * 8 <= dsaParameters.getQ().bitLength()); 
    }
    public static void testDSA(Factory factory, SecurityObject scope,
        IRand rand, boolean generate, KeyFlags keyFlags) throws Exception
    {
        println("DSA/EPHEMERAL");

        // указать идентификатор ключа
        String keyOID = aladdin.asn1.ansi.OID.X957_DSA; 
        
        // указать доверенную фабрику
        try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
        { 
            // получить фабрику кодирования ключей
            KeyFactory keyFactory = trustFactory.getKeyFactory(keyOID); 
            
            // указать способ использования ключа
            KeyUsage keyUsage = keyFactory.getKeyUsage(); 
            
            // раскодировать параметры алгоритма
            IParameters parameters = keyFactory.decodeParameters(
                aladdin.asn1.ansi.x957.DssParms.EPHEMERAL
            ); 
            // сгенерировать ключевую пару
            try (KeyPair keyPair = generateKeyPair(
                factory, scope, rand, trustFactory, null, generate, 
                keyOID, parameters, keyUsage, keyFlags))
            {
                // выполнить тест
                testDSA(trustFactory, null, keyPair, keyFlags); 
            }
            // удалить ключи контейнера
            finally { deleteKeys(scope); }
        }
        println();
    }
    public static void testDSA(Factory factory, SecurityStore scope,
        KeyPair keyPair, KeyFlags keyFlags) throws Exception
    {
        // закодировать параметры алгоритма подписи
        AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.X957_DSA), Null.INSTANCE
        );
        // закодировать параметры алгоритма хэширования
        AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
        );
        // указать параметры алгоритма подписи данных
        AlgorithmIdentifier signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.X957_DSA_SHA1), null
        );
        // получить алгоритм подписи данных
        try (SignData signAlgorithm = (SignData)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignData.class)) 
        {
            if (signAlgorithm != null) signTest(factory, scope,  
                hashParameters, signHashParameters, signParameters, keyPair, keyFlags
            ); 
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), Null.INSTANCE
        );
        // указать параметры алгоритма подписи данных
        signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_224), null
        );
        // получить алгоритм подписи данных
        try (SignData signAlgorithm = (SignData)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignData.class)) 
        {
            // при поддержке алгоритма
            if (signAlgorithm != null && hashSupportedDSA(keyPair.publicKey.parameters(), 28)) 
            {
                // выполнить тест
                signTest(factory, scope, hashParameters,
                    signHashParameters, signParameters, keyPair, keyFlags
                ); 
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), Null.INSTANCE
        );
        // указать параметры алгоритма подписи данных
        signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_256), null
        );
        // получить алгоритм подписи данных
        try (SignData signAlgorithm = (SignData)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignData.class)) 
        {
            // при поддержке алгоритма
            if (signAlgorithm != null && hashSupportedDSA(keyPair.publicKey.parameters(), 32)) 
            {
                // выполнить тест
                signTest(factory, scope, hashParameters,
                    signHashParameters, signParameters, keyPair, keyFlags
                ); 
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), Null.INSTANCE
        );
        // указать параметры алгоритма подписи данных
        signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_384), null
        );
        // получить алгоритм подписи данных
        try (SignData signAlgorithm = (SignData)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignData.class)) 
        {
            // при поддержке алгоритма
            if (signAlgorithm != null && hashSupportedDSA(keyPair.publicKey.parameters(), 48)) 
            {
                // выполнить тест
                signTest(factory, scope, hashParameters,
                    signHashParameters, signParameters, keyPair, keyFlags
                ); 
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), Null.INSTANCE
        );
        // указать параметры алгоритма подписи данных
        signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_512), null
        );
        // получить алгоритм подписи данных
        try (SignData signAlgorithm = (SignData)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignData.class)) 
        {
            // при поддержке алгоритма
            if (signAlgorithm != null && hashSupportedDSA(keyPair.publicKey.parameters(), 64)) 
            {
                // выполнить тест
                signTest(factory, scope, hashParameters,
                    signHashParameters, signParameters, keyPair, keyFlags
                ); 
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование DH
    ////////////////////////////////////////////////////////////////////////////
    public static void testDH(Factory factory, SecurityObject scope,
        IRand rand, boolean generate, KeyFlags keyFlags) throws Exception
    {
        println("DH/EPHEMERAL");

        // указать идентификатор ключа
        String keyOID = aladdin.asn1.ansi.OID.X942_DH_PUBLIC_KEY; 
        
        // указать доверенную фабрику
        try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
        { 
            // получить фабрику кодирования ключей
            KeyFactory keyFactory = trustFactory.getKeyFactory(keyOID); 
            
            // указать способ использования ключа
            KeyUsage keyUsage = keyFactory.getKeyUsage(); 
            
            // раскодировать параметры алгоритма
            IParameters parameters = keyFactory.decodeParameters(
                aladdin.asn1.ansi.x942.DomainParameters.EPHEMERAL
            ); 
            // сгенерировать ключевую пару
            try (KeyPair keyPair = generateKeyPair(
                factory, scope, rand, trustFactory, null, generate, 
                keyOID, parameters, keyUsage, keyFlags)) 
            {
                // выполнить тест
                testDH(trustFactory, null, keyPair, keyFlags); 
            }
            // удалить ключи контейнера
            finally { deleteKeys(scope); }
        }
        println();        
    }
    public static void testDH(Factory factory, SecurityStore scope, 
        KeyPair keyPair, KeyFlags keyFlags) throws Exception
    {
        // указать способ использования ключа
        KeyUsage keyUsage = new KeyUsage(KeyUsage.KEY_AGREEMENT); 
        
        // указать генератор случайных данных
        try (IRand rand = new aladdin.capi.Rand(null)) 
        {
            // сгенерировать ключевую пару
            try (KeyPair ephemeralKeyPair = factory.generateKeyPair(
                scope, rand, null, keyPair.publicKey.keyOID(), 
                keyPair.publicKey.parameters(), keyUsage, KeyFlags.NONE)) 
            {
                testDH(factory, scope, rand, keyPair, keyFlags, ephemeralKeyPair, 
                    aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_SSDH, 
                    aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_ESDH
                ); 
            }
        }
    }
    private static void testDH(Factory factory, SecurityStore scope,
        IRand rand, KeyPair keyPair, KeyFlags keyFlags, 
        KeyPair ephemeralKeyPair, String... algOIDs) throws Exception
    {
        {
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_RC2_128_WRAP),         
                aladdin.asn1.ansi.rsa.RC2ParameterVersion.getVersion(128)
            ); 
            // выполнить тест
            testDH(factory, scope, keyPair, keyFlags, 
                ephemeralKeyPair, algOIDs, wrapParameters, 8
            ); 
        }{
            // сгенерировать синхропосылку
            byte[] iv = new byte[8]; rand.generate(iv, 0, iv.length); 

            // закодировать параметры алгоритма шифрования
            AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_CBC), new OctetString(iv)
            ); 
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_PWRI_KEK),         
                cipherParameters
            ); 
            // выполнить тест
            testDH(factory, scope, keyPair, keyFlags, 
                ephemeralKeyPair, algOIDs, wrapParameters, 8
            ); 
        }{
            // сгенерировать синхропосылку
            byte[] iv = new byte[8]; rand.generate(iv, 0, iv.length); 

            // закодировать параметры алгоритма шифрования
            AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_TDES192_CBC), new OctetString(iv)
            ); 
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_PWRI_KEK),         
                cipherParameters
            ); 
            // выполнить тест
            testDH(factory, scope, keyPair, keyFlags, 
                ephemeralKeyPair, algOIDs, wrapParameters, 24
            ); 
        }{
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_TDES192_WRAP), Null.INSTANCE
            ); 
            // выполнить тест
            testDH(factory, scope, keyPair, keyFlags, 
                ephemeralKeyPair, algOIDs, wrapParameters, 24
            ); 
        }{
            // сгенерировать синхропосылку
            byte[] iv = new byte[16]; rand.generate(iv, 0, iv.length); 

            // закодировать параметры алгоритма шифрования
            AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES128_CBC), new OctetString(iv)
            ); 
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_PWRI_KEK),         
                cipherParameters
            ); 
            // выполнить тест
            testDH(factory, scope, keyPair, keyFlags, 
                ephemeralKeyPair, algOIDs, wrapParameters, 16
            ); 
        }{
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES128_WRAP), Null.INSTANCE
            ); 
            // выполнить тест
            testDH(factory, scope, keyPair, keyFlags, 
                ephemeralKeyPair, algOIDs, wrapParameters, 16
            ); 
        }{
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES128_WRAP_PAD), Null.INSTANCE
            ); 
            // выполнить тест
            testDH(factory, scope, keyPair, keyFlags, 
                ephemeralKeyPair, algOIDs, wrapParameters, 16
            ); 
        }{
            // сгенерировать ключ и синхропосылку
            byte[] iv = new byte[16]; rand.generate(iv, 0, iv.length); 

            // закодировать параметры алгоритма шифрования
            AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_CBC), new OctetString(iv)
            ); 
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_PWRI_KEK),         
                cipherParameters
            ); 
            // выполнить тест
            testDH(factory, scope, keyPair, keyFlags, 
                ephemeralKeyPair, algOIDs, wrapParameters, 24
            ); 
        }{
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_WRAP), Null.INSTANCE
            ); 
            // выполнить тест
            testDH(factory, scope, keyPair, keyFlags, 
                ephemeralKeyPair, algOIDs, wrapParameters, 24
            ); 
        }{
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_WRAP_PAD), Null.INSTANCE
            ); 
            // выполнить тест
            testDH(factory, scope, keyPair, keyFlags, 
                ephemeralKeyPair, algOIDs, wrapParameters, 24
            ); 
        }{
            // сгенерировать синхропосылку
            byte[] iv = new byte[16]; rand.generate(iv, 0, iv.length); 

            // закодировать параметры алгоритма шифрования
            AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES256_CBC), new OctetString(iv)
            ); 
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_PWRI_KEK),         
                cipherParameters
            ); 
            // выполнить тест
            testDH(factory, scope, keyPair, keyFlags, 
                ephemeralKeyPair, algOIDs, wrapParameters, 32
            ); 
        }{
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES256_WRAP), Null.INSTANCE
            ); 
            // выполнить тест
            testDH(factory, scope, keyPair, keyFlags, 
                ephemeralKeyPair, algOIDs, wrapParameters, 32
            ); 
        }{
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES256_WRAP_PAD), Null.INSTANCE
            ); 
            // выполнить тест
            testDH(factory, scope, keyPair, keyFlags, 
                ephemeralKeyPair, algOIDs, wrapParameters, 32
            ); 
        }
    }
    private static void testDH(Factory factory, SecurityStore scope,
        KeyPair keyPair, KeyFlags keyFlags, KeyPair ephemeralKeyPair, 
        String[] algOIDs, AlgorithmIdentifier wrapParameters, int keySize) throws Exception
    {
        for (String algOID : algOIDs)
        {    
            // закодировать параметры алгоритма 
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(algOID), wrapParameters
            ); 
            // получить алгоритм согласования ключа
            try (ITransportAgreement agreement = (ITransportAgreement)
                keyPair.privateKey.factory().createAlgorithm(
                keyPair.privateKey.scope(), parameters, ITransportAgreement.class))
            {
                // при наличии алгоритма
                if (agreement != null)
                {
                    // выполнить тест
                    transportAgreementTest(factory, scope, parameters,
                        keyPair, keyFlags, ephemeralKeyPair, new int[] {keySize}
                    );
                }
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование ECDSA/ECDH
    ////////////////////////////////////////////////////////////////////////////
    public static void testEC(Factory factory, SecurityObject scope, IRand rand, 
        boolean generate, KeyFlags keyFlags, String paramOID) throws Exception
    {
        println("EC/%1$s", paramOID);
        
        // указать идентификатор ключа
        String keyOID = aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY; 
        
        // указать доверенную фабрику
        try (Factory trustFactory = new aladdin.capi.ansi.Factory()) 
        { 
            // получить фабрику кодирования ключей
            KeyFactory keyFactory = trustFactory.getKeyFactory(keyOID); 
            
            // указать способ использования ключа
            KeyUsage keyUsage = keyFactory.getKeyUsage(); 

            // раскодировать параметры алгоритма
            IParameters parameters = keyFactory.decodeParameters(
                new ObjectIdentifier(paramOID)
            ); 
            // сгенерировать ключевую пару
            try (KeyPair keyPair = generateKeyPair(
                factory, scope, rand, trustFactory, null, generate, 
                keyOID, parameters, keyUsage, keyFlags)) 
            {
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.DIGITAL_SIGNATURE))
                { 
                    // выполнить тест
                    testECDSA(trustFactory, null, keyPair, keyFlags); 
                }
                // при допустимости теста
                if (keyUsage.containsAny(KeyUsage.KEY_AGREEMENT))
                { 
                    // выполнить тест
                    testECDH(trustFactory, null, keyPair, keyFlags); 
                }
            }
            // удалить ключи контейнера
            finally { deleteKeys(scope); }
        }
        println();
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование ECDSA
    ////////////////////////////////////////////////////////////////////////////
    private static boolean hashSupportedECDSA(IParameters parameters, int hashSize) 
    { 
        // преобразовать тип параметров
        aladdin.capi.ansi.x962.IParameters ecParameters = 
            (aladdin.capi.ansi.x962.IParameters)parameters; 

        // проверить размер хэш-значения
        return (hashSize * 8 <= ecParameters.getOrder().bitLength()); 
    }
    public static void testECDSA(Factory factory, Container container) throws Exception 
    {
        println("ECDSA");
        
        // закодировать параметры алгоритма хэширования
        AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
        ); 
        // закодировать параметры алгоритма подписи
        AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1), Null.INSTANCE
        );
        if (container != null)
        {
            // указать алгоритм хэширования
            try (Hash hashAlgorithm = (Hash)container.provider().createAlgorithm(
                container.store(), hashParameters, Hash.class))
            {
                // получить алгоритм выработки подписи
                try (SignHash signHash = (SignHash)container.provider().createAlgorithm(
                    container.store(), signHashParameters, SignHash.class))
                {
                    // выполнить тест
                    aladdin.capi.ansi.sign.ecdsa.SignHash.test(
                        factory, container, signHash, hashAlgorithm
                    );
                }
                // удалить ключи из контейнера
                finally { container.deleteKeys(); }
                
                // вывести сообщение
                print("OK  ");

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)container.provider().createAlgorithm(
                    container.store(), signHashParameters, VerifyHash.class))
                {
                    // выполнить тест
                    aladdin.capi.ansi.sign.ecdsa.VerifyHash.test(
                        verifyHash, hashAlgorithm
                    );
                }
                // вывести сообщение
                print("OK  ");
            }
        }
        else {
            // указать алгоритм хэширования
            try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                null, hashParameters, Hash.class))
            {
                // получить алгоритм выработки подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    null, signHashParameters, SignHash.class))
                {
                    // выполнить тест
                    aladdin.capi.ansi.sign.ecdsa.SignHash.test(
                        factory, container, signHash, hashAlgorithm
                    );
                }
                // вывести сообщение
                print("OK  ");
                
                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    null, signHashParameters, VerifyHash.class))
                {
                    // выполнить тест
                    aladdin.capi.ansi.sign.ecdsa.VerifyHash.test(
                        verifyHash, hashAlgorithm
                    );
                }
                // вывести сообщение
                print("OK  ");
            }
        }
        println();
    }
    public static void testECDSA(Factory factory, SecurityStore scope,
        KeyPair keyPair, KeyFlags keyFlags) throws Exception
    {
        // закодировать параметры алгоритма хэширования
        AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
        );
        // указать параметры алгоритма подписи данных
        AlgorithmIdentifier signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1), null
        );
        // получить алгоритм подписи данных
        try (SignData signAlgorithm = (SignData)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignData.class)) 
        {
            if (signAlgorithm != null) signTest(factory, scope, 
                hashParameters, signParameters, signParameters, keyPair, keyFlags 
            ); 
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), Null.INSTANCE
        );
        // указать параметры алгоритма подписи данных
        signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_256), null
        );
        // получить алгоритм подписи данных
        try (SignData signAlgorithm = (SignData)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignData.class)) 
        {
            // при поддержке алгоритма
            if (signAlgorithm != null && hashSupportedECDSA(keyPair.publicKey.parameters(), 28)) 
            {
                // выполнить тест
                signTest(factory, scope, hashParameters, 
                    signParameters, signParameters, keyPair, keyFlags
                ); 
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), Null.INSTANCE
        );
        // указать параметры алгоритма подписи данных
        signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_256), null
        );
        // получить алгоритм подписи данных
        try (SignData signAlgorithm = (SignData)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignData.class)) 
        {
            // при поддержке алгоритма
            if (signAlgorithm != null && hashSupportedECDSA(keyPair.publicKey.parameters(), 32)) 
            {
                // выполнить тест
                signTest(factory, scope, hashParameters, 
                    signParameters, signParameters, keyPair, keyFlags
                ); 
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), Null.INSTANCE
        );
        // указать параметры алгоритма подписи данных
        signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_384), null
        );
        // получить алгоритм подписи данных
        try (SignData signAlgorithm = (SignData)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignData.class)) 
        {
            // при поддержке алгоритма
            if (signAlgorithm != null && hashSupportedECDSA(keyPair.publicKey.parameters(), 48)) 
            {
                // выполнить тест
                signTest(factory, scope, hashParameters, 
                    signParameters, signParameters, keyPair, keyFlags
                ); 
            }
        }
        // закодировать параметры алгоритма хэширования
        hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), Null.INSTANCE
        );
        // указать параметры алгоритма подписи данных
        signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_512), null
        );
        // получить алгоритм подписи данных
        try (SignData signAlgorithm = (SignData)keyPair.privateKey.factory().
            createAlgorithm(keyPair.privateKey.scope(), signParameters, SignData.class)) 
        {
            // при поддержке алгоритма
            if (signAlgorithm != null && hashSupportedECDSA(keyPair.publicKey.parameters(), 64)) 
            {
                // выполнить тест
                signTest(factory, scope, hashParameters, 
                    signParameters, signParameters, keyPair, keyFlags
                ); 
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Тестирование ECDH
    ////////////////////////////////////////////////////////////////////////////
    public static void testECDH(Factory factory, SecurityStore scope, 
        KeyPair keyPair, KeyFlags keyFlags) throws Exception
    {
        // указать способ использования ключа
        KeyUsage keyUsage = new KeyUsage(KeyUsage.KEY_AGREEMENT); 
        
        // указать генератор случайных данных
        try (IRand rand = new aladdin.capi.Rand(null)) 
        {
            // сгенерировать ключевую пару
            try (KeyPair ephemeralKeyPair = factory.generateKeyPair(
                scope, rand, null, keyPair.publicKey.keyOID(), 
                keyPair.publicKey.parameters(), keyUsage, KeyFlags.NONE)) 
            {
                testDH(factory, scope, rand, keyPair, keyFlags, ephemeralKeyPair, 
                    aladdin.asn1.ansi.OID.X963_ECDH_STD_SHA1, 
                    aladdin.asn1.ansi.OID.CERTICOM_ECDH_STD_SHA2_256, 
                    aladdin.asn1.ansi.OID.CERTICOM_ECDH_STD_SHA2_384, 
                    aladdin.asn1.ansi.OID.CERTICOM_ECDH_STD_SHA2_512, 
                    aladdin.asn1.ansi.OID.X963_ECDH_COFACTOR_SHA1, 
                    aladdin.asn1.ansi.OID.CERTICOM_ECDH_COFACTOR_SHA2_256, 
                    aladdin.asn1.ansi.OID.CERTICOM_ECDH_COFACTOR_SHA2_384, 
                    aladdin.asn1.ansi.OID.CERTICOM_ECDH_COFACTOR_SHA2_512
                ); 
            }
        }
    }
}

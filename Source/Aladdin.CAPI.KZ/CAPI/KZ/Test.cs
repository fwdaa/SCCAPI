using System;

namespace Aladdin.CAPI.KZ
{
    public class Test : CAPI.Test
    {
        public static void Entry()
        {
            using (CAPI.Factory factory = new KZ.Factory()) 
            {
                SecurityStore scope = null; 
            
                ////////////////////////////////////////////////////////////////////
                // Алгоритмы хэширования
                ////////////////////////////////////////////////////////////////////
                ANSI.Test.TestSHA1    (factory, scope);
                ANSI.Test.TestSHA2_224(factory, scope);
                ANSI.Test.TestSHA2_256(factory, scope);
                ANSI.Test.TestSHA2_384(factory, scope);
                ANSI.Test.TestSHA2_512(factory, scope);

                GOST.Test.TestGOSTR3411_1994(
                    factory, scope, ASN1.GOST.OID.hashes_test
                ); 
                GOST.Test.TestGOSTR3411_1994(
                    factory, scope, ASN1.GOST.OID.hashes_cryptopro
                ); 
                TestGOST34311_1994(factory, scope); 
            
                ////////////////////////////////////////////////////////////////////
                // Алгоритмы вычисления имитовставки
                ////////////////////////////////////////////////////////////////////
                ANSI.Test.TestHMAC_SHA1    (factory, scope); 
                ANSI.Test.TestHMAC_SHA2_224(factory, scope); 
                ANSI.Test.TestHMAC_SHA2_256(factory, scope); 
                ANSI.Test.TestHMAC_SHA2_384(factory, scope); 
                ANSI.Test.TestHMAC_SHA2_512(factory, scope); 
            
                GOST.Test.TestHMAC_GOSTR3411_1994(
                    factory, scope, ASN1.GOST.OID.hashes_test
                ); 
                GOST.Test.TestHMAC_GOSTR3411_1994(
                    factory, scope, ASN1.GOST.OID.hashes_cryptopro
                ); 
                ////////////////////////////////////////////////////////////////////
                // Алгоритмы шифрования
                ////////////////////////////////////////////////////////////////////
                ANSI.Test.TestRC2 (factory, scope); 
                ANSI.Test.TestRC4 (factory, scope); 
                ANSI.Test.TestTDES(factory, scope); 
                ANSI.Test.TestAES (factory, scope); 
            
                TestGOST28147(factory, scope); 
            
                // указать генератор случайных данных
                using (IRand rand = new CAPI.Rand(null))
                { 
                    ////////////////////////////////////////////////////////////////////
                    // RSA
                    ////////////////////////////////////////////////////////////////////
                    int[] кeySizes = KeySizes.Range(1, 32); 

                    TestRSA(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.KZ.OID.gamma_key_rsa_1024, кeySizes
                    ); 
                    TestRSA(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.KZ.OID.gamma_key_rsa_1536, кeySizes
                    ); 
                    TestRSA(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.KZ.OID.gamma_key_rsa_2048, кeySizes
                    ); 
                    TestRSA(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.KZ.OID.gamma_key_rsa_1024_xch, кeySizes
                    ); 
                    TestRSA(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.KZ.OID.gamma_key_rsa_1536_xch, кeySizes
                    ); 
                    TestRSA(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.KZ.OID.gamma_key_rsa_2048_xch, кeySizes
                    ); 
                    ////////////////////////////////////////////////////////////////////
                    // ГОСТ 34310
                    ////////////////////////////////////////////////////////////////////
                    TestGOST34310(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.KZ.OID.gamma_key_ec256_512_a
                    ); 
                    TestGOST34310(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.KZ.OID.gamma_key_ec256_512_b
                    ); 
                    TestGOST34310(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.KZ.OID.gamma_key_ec256_512_c
                    ); 
                    TestGOST34310(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.KZ.OID.gamma_key_ec256_512_a_xch
                    ); 
                    TestGOST34310(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.KZ.OID.gamma_key_ec256_512_b_xch
                    ); 
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Алгоритмы хэширования
        ////////////////////////////////////////////////////////////////////////////
        public static void TestGOST34311_1994(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Hash.GOST34311");
        
            // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gost34311_95), ASN1.Null.Instance
            ); 
            // создать алгоритм хэширования
            using (Hash hashAlgorithm = factory.CreateAlgorithm<Hash>(scope, parameters)) 
            {
                // выполнить тест
                GOST.Hash.GOSTR3411_1994.TestTest(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new KZ.Factory()) 
                {
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Алгоритмы шифрования
        ////////////////////////////////////////////////////////////////////////////
        public static void TestGOST28147(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Cipher.GOST28147"); byte[] iv = new byte[8]; 
        
            // указать допустимые размеры
            int[] dataSizes = new int[] { 0, 1, 7, 8, 9, 15, 16, 17, 1023, 1024, 1025 }; 

		    // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost_ecb), ASN1.Null.Instance
            ); 
            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
            { 
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new KZ.Factory()) 
                {
                    // выполнить тест
                    CipherTest(cipher, PaddingMode.PKCS5, trustFactory, null, parameters, dataSizes);
                }
            }
            // сгенерировать синхропосылку
            Generate(iv, 0, iv.Length); 
        
	        // указать параметры алгоритма
	        parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost_cbc), new ASN1.OctetString(iv)
            ); 
            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
            { 
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new KZ.Factory()) 
                {
                    // выполнить тест
                    CipherTest(cipher, PaddingMode.PKCS5, trustFactory, null, parameters, dataSizes);
                }
            }
            // сгенерировать синхропосылку
            Generate(iv, 0, iv.Length); 
        
	        // указать параметры алгоритма
	        parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost_cfb), new ASN1.OctetString(iv)
            ); 
            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
            { 
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new KZ.Factory()) 
                {
                    // выполнить тест
                    CipherTest(cipher, PaddingMode.Any, trustFactory, null, parameters, dataSizes);
                }
            }
            // сгенерировать синхропосылку
            Generate(iv, 0, iv.Length); 
        
	        // указать параметры алгоритма
	        parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost_ofb), new ASN1.OctetString(iv)
            ); 
            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
            { 
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new KZ.Factory()) 
                {
                    // выполнить тест
                    CipherTest(cipher, PaddingMode.Any, trustFactory, null, parameters, dataSizes);
                }
            }
            // сгенерировать синхропосылку
            Generate(iv, 0, iv.Length); 
        
	        // указать параметры алгоритма
	        parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost_cnt), new ASN1.OctetString(iv)
            ); 
            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
            { 
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new KZ.Factory()) 
                {
                    // выполнить тест
                    CipherTest(cipher, PaddingMode.Any, trustFactory, null, parameters, dataSizes);
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // RSA
        ////////////////////////////////////////////////////////////////////////////
        public static void TestRSA(CAPI.Factory factory, SecurityObject scope, 
            IRand rand, bool generate, KeyFlags keyFlags, string keyOID, int[] keySizes) 
        {
            WriteLine("RSA/{0}", keyOID);
        
            // указать доверенную фабрику
            using (Factory trustFactory = new KZ.Factory()) 
            {
                // получить фабрику кодирования
                KeyFactory keyFactory = trustFactory.GetKeyFactory(keyOID); 

                // указать способ использования ключа
                KeyUsage keyUsage = keyFactory.GetKeyUsage(); 
        
                // раскодировать параметры алгоритма
                IParameters parameters = keyFactory.DecodeParameters(ASN1.Null.Instance); 

                // сгенерировать ключевую пару
                using (KeyPair keyPair = GenerateKeyPair(
                    factory, scope, rand, trustFactory, null, generate, 
                    keyOID, parameters, keyUsage, keyFlags))
                try { 
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.DigitalSignature) != KeyUsage.None)
                    { 
                        // выполнить тесты
                        ANSI.Test.TestSignRSA(trustFactory, null, keyPair, keyFlags); 
                    }
                    // при допустимости теста
                    if (((keyUsage & KeyUsage.DataEncipherment) != KeyUsage.None) || 
                        ((keyUsage & KeyUsage.KeyEncipherment ) != KeyUsage.None))
                    { 
                        // выполнить тесты
                        ANSI.Test.TestKeyxRSA(trustFactory, null, keyPair, keyFlags, keySizes); 
                    }
                }
                // удалить ключи контейнера
                finally { DeleteKeys(scope); }
            }
            WriteLine();
        }
        ////////////////////////////////////////////////////////////////////////////
        // ГОСТ P 34.10-2001
        ////////////////////////////////////////////////////////////////////////////
        public static void TestGOST34310(CAPI.Factory factory, SecurityObject scope, 
            IRand rand, bool generate, KeyFlags keyFlags, string keyOID) 
        {
            WriteLine("GOST34310/{0}", keyOID);
        
            // указать доверенную фабрику
            using (Factory trustFactory = new KZ.Factory()) 
            {
                // получить фабрику кодирования
                KeyFactory keyFactory = trustFactory.GetKeyFactory(keyOID); 

                // указать способ использования ключа
                KeyUsage keyUsage = keyFactory.GetKeyUsage(); 
        
                // раскодировать параметры алгоритма
                IParameters parameters = keyFactory.DecodeParameters(ASN1.Null.Instance); 

                // сгенерировать ключевую пару
                using (KeyPair keyPair = GenerateKeyPair(
                    factory, scope, rand, trustFactory, null, generate, 
                    keyOID, parameters, keyUsage, keyFlags))
                try { 
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.DigitalSignature) != KeyUsage.None)
                    { 
                        // указать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gost34310_2004), ASN1.Null.Instance
                        ); 
                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gost34311_95), ASN1.Null.Instance
                        ); 
                        // указать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier signParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gost34310_34311_2004_t), null
                        ); 
                        // выполнить тест
                        SignTest(trustFactory, null, hashParameters, 
                            signHashParameters, signParameters, keyPair, keyFlags 
                        );
                        // указать параметры алгоритма хэширования
                        hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_94), 
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.hashes_cryptopro) 
                        );
                        // указать параметры алгоритма
                        signParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gostR3410_R3411_2001_cp), null
                        ); 
                        // выполнить тест
                        SignTest(trustFactory, null, hashParameters, 
                            signHashParameters, signParameters, keyPair, keyFlags 
                        );
                    }
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.KeyAgreement) != KeyUsage.None)
                    { 
                        // закодировать параметры алгоритма 
                        ASN1.ISO.AlgorithmIdentifier agreementParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gost28147), ASN1.Null.Instance
                        ); 
                        // выполнить тест
                        GOST.Test.TestAgreementGOSTR3410(trustFactory, null, 
                            keyPair, keyFlags, null, agreementParameters, new int[] {32}
                        ); 
                    }
                }
                // удалить ключи контейнера
                finally { DeleteKeys(scope); }
            }
            WriteLine();
        }
    }
}

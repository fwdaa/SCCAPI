using System;

namespace Aladdin.CAPI.STB
{
    public class Test : CAPI.Test
    {
        public static void Entry()
        {
            using (Factory factory = new STB.Factory()) 
            {
                SecurityStore scope = null; 
            
                ////////////////////////////////////////////////////////////////////
                // Симметричные алгоритмы
                ////////////////////////////////////////////////////////////////////
                TestHash_STB11761  (factory, scope); 
                TestHash_STB34101  (factory, scope); 
                TestMAC_STB34101   (factory, scope);
                TestCipher_STB34101(factory, scope);
                TestKDF_STB34101   (factory, scope);
                TestWrapSTB34101   (factory, scope);

                // указать генератор случайных данных
                using (IRand rand = new CAPI.Rand(null))
                { 
                    ////////////////////////////////////////////////////////////////////
                    // СТБ 1176.2
                    ////////////////////////////////////////////////////////////////////
                    TestSTB11762_BDS(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.STB.OID.stb11762_params3_bds
                    );
                    TestSTB11762_BDS(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.STB.OID.stb11762_params6_bds
                    );
                    TestSTB11762_BDS(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.STB.OID.stb11762_params10_bds
                    );
                    TestSTB11762_BDSPRO(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.STB.OID.stb11762_params3_bds
                    );
                    TestSTB11762_BDSPRO(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.STB.OID.stb11762_params6_bds
                    );
                    TestSTB11762_BDSPRO(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.STB.OID.stb11762_params10_bds
                    );
                    TestSTB11762_BDS_BDH(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.STB.OID.stb11762_params3
                    );
                    TestSTB11762_BDS_BDH(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.STB.OID.stb11762_params6
                    );
                    TestSTB11762_BDS_BDH(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.STB.OID.stb11762_params10
                    );
                    TestSTB11762_BDSPRO_BDH(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.STB.OID.stb11762_params3
                    );
                    TestSTB11762_BDSPRO_BDH(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.STB.OID.stb11762_params6
                    );
                    TestSTB11762_BDSPRO_BDH(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.STB.OID.stb11762_params10
                    );
                    ////////////////////////////////////////////////////////////////////
                    // СТБ 34.101
                    ////////////////////////////////////////////////////////////////////
                    TestSTB34101(factory, null);
                    TestSTB34101(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.STB.OID.stb34101_bign_curve256_v1
                    );
                    TestSTB34101(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.STB.OID.stb34101_bign_curve384_v1
                    );
                    TestSTB34101(factory, scope, rand, 
                        true, KeyFlags.None, ASN1.STB.OID.stb34101_bign_curve512_v1
                    );
                }
            }
        }
	    ///////////////////////////////////////////////////////////////////////////
	    // Алгоритмы хэширования
	    ///////////////////////////////////////////////////////////////////////////
        public static void TestHash_STB11761(CAPI.Factory factory, SecurityStore scope) 
        {
            WriteLine("Hash.STB11761");
        
		    // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11761_hash0), ASN1.Null.Instance
            ); 
            // создать алгоритм хэширования
            using (CAPI.Hash algorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters)) 
            {
                // выполнить тест
                Hash.STB11761.Test(algorithm);
            }
        }
        public static void TestHash_STB34101(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Hash.STB34101");
            
		    // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_hash), ASN1.Null.Instance
            ); 
            // создать алгоритм хэширования
            using (CAPI.Hash algorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters)) 
            {
                // выполнить тест
                Hash.STB34101.Test(algorithm);
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Алгоритмы вычисления имитовставки
        ////////////////////////////////////////////////////////////////////////////
        public static void TestMAC_STB34101(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("MAC.STB34101");
            
		    // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_mac_256), ASN1.Null.Instance
            ); 
            // создать алгоритм выработки имитовставки
            using (Mac algorithm = factory.CreateAlgorithm<Mac>(scope, parameters))
            {
                // выполнить тест
                MAC.STB34101.Test(algorithm);
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Алгоритмы шифрования
        ////////////////////////////////////////////////////////////////////////////
        public static void TestCipher_STB34101(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Cipher.STB34101");
        
            // создать алгоритм шифрования
            using (IBlockCipher blockCipher = new Cipher.STB34101(factory, scope, 32))
            {
                // выполнить тест
                Engine.STB34101.Test(blockCipher);
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Алгоритмы наследования ключа
        ////////////////////////////////////////////////////////////////////////////
        public static void TestKDF_STB34101(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("KeyDerive.STB34101");
            
		    // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_keyPrep), 
                new ASN1.OctetString(new byte[] {
                    (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
                    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                    (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                })
            ); 
            // создать алгоритм наследования ключа
            using (KeyDerive algorithm = factory.CreateAlgorithm<KeyDerive>(scope, parameters)) 
            {
                // выполнить тест
                Derive.STB34101.Test1(algorithm);
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Алгоритмы шифрования ключа
        ////////////////////////////////////////////////////////////////////////////
        public static void TestWrapSTB34101(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("KeyWrap.STB34101");
        
		    // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_keyWrap_256), ASN1.Null.Instance
            );
            // создать алгоритм шифрования ключа
            using (KeyWrap algorithm = factory.CreateAlgorithm<KeyWrap>(scope, parameters)) 
            {
                // выполнить тест
                Wrap.STB34101.Test(algorithm);
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // СТБ 1176.2
        ////////////////////////////////////////////////////////////////////////////
        public static void TestSTB11762_BDS(CAPI.Factory factory, SecurityObject scope, 
            IRand rand, bool generate, KeyFlags keyFlags, string paramOID) 
        {
            WriteLine("STB11762.BDS/{0}", paramOID);
        
            // указать идентификатор ключа
            string keyOID = ASN1.STB.OID.stb11762_bds_pubKey; 
        
            // указать способ использования ключа
            KeyUsage keyUsage = KeyUsage.DigitalSignature; 
        
            // указать доверенную фабрику
            using (Factory trustFactory = new STB.Factory()) 
            {
                // закодировать параметры ключа
                ASN1.IEncodable encodedParameters = new ASN1.Explicit<ASN1.ObjectIdentifier>(
                    ASN1.Tag.Context(0), new ASN1.ObjectIdentifier(paramOID)
                ); 
                // получить фабрику кодирования
                KeyFactory keyFactory = trustFactory.GetKeyFactory(keyOID); 

                // раскодировать параметры алгоритма
                IParameters parameters = keyFactory.DecodeParameters(encodedParameters); 

                // сгенерировать ключевую пару
                using (KeyPair keyPair = GenerateKeyPair(
                    factory, scope, rand, trustFactory, null, generate, 
                    keyOID, parameters, keyUsage, keyFlags))
                try {
                    // закодировать параметры алгоритма хэширования
                    ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11761_hashA), ASN1.Null.Instance
                    ); 
                    // закодировать параметры алгоритма подписи
                    ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_sign), ASN1.Null.Instance
                    );
                    // закодировать параметры алгоритма подписи
                    ASN1.ISO.AlgorithmIdentifier signParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_sign), null
                    );
                    // выполнить тест
                    SignTest(trustFactory, null, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags
                    );
                }
                // удалить ключи контейнера
                finally { DeleteKeys(scope); }
            }
            WriteLine();        
        }
        public static void TestSTB11762_BDSPRO(CAPI.Factory factory, SecurityObject scope, 
            IRand rand, bool generate, KeyFlags keyFlags, string paramOID)
        {
            WriteLine("STB11762.BDSPRO/{0}", paramOID);
        
            // указать идентификатор ключа
            string keyOID = ASN1.STB.OID.stb11762_pre_bds_pubKey; 
        
            // указать способ использования ключа
            KeyUsage keyUsage = KeyUsage.DigitalSignature; 
        
            // указать доверенную фабрику
            using (Factory trustFactory = new STB.Factory()) 
            {
                // закодировать параметры ключа
                ASN1.IEncodable encodedParameters = new ASN1.Explicit<ASN1.ObjectIdentifier>(
                    ASN1.Tag.Context(0), new ASN1.ObjectIdentifier(paramOID)
                ); 
                // получить фабрику кодирования
                KeyFactory keyFactory = trustFactory.GetKeyFactory(keyOID); 

                // раскодировать параметры алгоритма
                IParameters parameters = keyFactory.DecodeParameters(encodedParameters); 

                // сгенерировать ключевую пару
                using (KeyPair keyPair = GenerateKeyPair(
                    factory, scope, rand, trustFactory, null, generate, 
                    keyOID, parameters, keyUsage, keyFlags))
                try {
                    // закодировать параметры алгоритма хэширования
                    ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11761_hashA), ASN1.Null.Instance
                    ); 
                    // закодировать параметры алгоритма подписи
                    ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_sign), ASN1.Null.Instance
                    );
                    // закодировать параметры алгоритма подписи
                    ASN1.ISO.AlgorithmIdentifier signParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_pre_sign), null
                    );
                    // выполнить тест
                    SignTest(trustFactory, null, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags
                    );
                }
                // удалить ключи контейнера
                finally { DeleteKeys(scope); }
            }
            WriteLine();        
        }
        public static void TestSTB11762_BDS_BDH(CAPI.Factory factory, SecurityObject scope, 
            IRand rand, bool generate, KeyFlags keyFlags, string paramOID) 
        {
            WriteLine("STB11762.BDS_BDH/{0}", paramOID);

            // указать идентификатор ключа
            string keyOID = ASN1.STB.OID.stb11762_bdsbdh_pubKey; int[] keySizes = new int[] {32}; 

            // указать доверенную фабрику
            using (Factory trustFactory = new STB.Factory()) 
            {
                // получить фабрику кодирования
                KeyFactory keyFactory = trustFactory.GetKeyFactory(keyOID); 

                // указать способ использования ключа
                KeyUsage keyUsage = keyFactory.GetKeyUsage(); 
        
                // закодировать параметры ключа
                ASN1.IEncodable encodedParameters = new ASN1.Explicit<ASN1.ObjectIdentifier>(
                    ASN1.Tag.Context(2), new ASN1.ObjectIdentifier(paramOID)
                ); 
                // раскодировать параметры алгоритма
                IParameters parameters = keyFactory.DecodeParameters(encodedParameters); 

                // сгенерировать ключевую пару
                using (KeyPair keyPair = GenerateKeyPair(
                    factory, scope, rand, trustFactory, null, generate, 
                    keyOID, parameters, keyUsage, keyFlags)) 
                try {
                    // при допустимости использования ключа
                    if ((keyUsage & KeyUsage.DigitalSignature) != KeyUsage.None)
                    {
                        // закодировать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11761_hashA), ASN1.Null.Instance
                        ); 
                        // закодировать параметры алгоритма подписи
                        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_sign), ASN1.Null.Instance
                        );
                        // закодировать параметры алгоритма подписи
                        ASN1.ISO.AlgorithmIdentifier signParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_sign), null
                        );
                        // выполнить тест
                        SignTest(trustFactory, null, hashParameters, 
                            signHashParameters, signParameters, keyPair, keyFlags
                        );
                    }
                    // при допустимости использования ключа
                    if ((keyUsage & KeyUsage.KeyEncipherment) != KeyUsage.None)
                    {
                        // указать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier transportParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_bdh_keyTrans), ASN1.Null.Instance
                        ); 
                        // выполнить тест
                        TransportKeyTest(trustFactory, null, 
                            transportParameters, keyPair, keyFlags, keySizes
                        );
                    }
                }
                // удалить ключи контейнера
                finally { DeleteKeys(scope); }
            }
            WriteLine();
        }
        public static void TestSTB11762_BDSPRO_BDH(CAPI.Factory factory, SecurityObject scope, 
            IRand rand, bool generate, KeyFlags keyFlags, String paramOID)
        {
            WriteLine("STB11762.BDSPRO_BDH/{0}", paramOID);
        
            // указать идентификатор ключа
            string keyOID = ASN1.STB.OID.stb11762_pre_bdsbdh_pubKey; int[] keySizes = new int[] {32}; 
        
            // указать доверенную фабрику
            using (Factory trustFactory = new STB.Factory()) 
            {
                // получить фабрику кодирования
                KeyFactory keyFactory = trustFactory.GetKeyFactory(keyOID); 

                // указать способ использования ключа
                KeyUsage keyUsage = keyFactory.GetKeyUsage(); 
        
                // закодировать параметры ключа
                ASN1.IEncodable encodedParameters = new ASN1.Explicit<ASN1.ObjectIdentifier>(
                    ASN1.Tag.Context(2), new ASN1.ObjectIdentifier(paramOID)
                ); 
                // раскодировать параметры алгоритма
                IParameters parameters = keyFactory.DecodeParameters(encodedParameters); 

                // сгенерировать ключевую пару
                using (KeyPair keyPair = GenerateKeyPair(
                    factory, scope, rand, trustFactory, null, generate, 
                    keyOID, parameters, keyUsage, keyFlags)) 
                try {
                    // при допустимости использования ключа
                    if ((keyUsage & KeyUsage.DigitalSignature) != KeyUsage.None)
                    {
                        // закодировать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11761_hashA), ASN1.Null.Instance
                        ); 
                        // закодировать параметры алгоритма подписи
                        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_sign), ASN1.Null.Instance
                        );
                        // закодировать параметры алгоритма подписи
                        ASN1.ISO.AlgorithmIdentifier signParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_pre_sign), null
                        );
                        // выполнить тест
                        SignTest(trustFactory, null, hashParameters, 
                            signHashParameters, signParameters, keyPair, keyFlags
                        );
                    }
                    // при допустимости использования ключа
                    if ((keyUsage & KeyUsage.KeyEncipherment) != KeyUsage.None)
                    {
                        // указать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier transportParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb11762_bdh_keyTrans), ASN1.Null.Instance
                        ); 
                        // выполнить тест
                        TransportKeyTest(trustFactory, null, 
                            transportParameters, keyPair, keyFlags, keySizes
                        );
                    }
                }
                // удалить ключи контейнера
                finally { DeleteKeys(scope); }
            }
            WriteLine();
        }
        ////////////////////////////////////////////////////////////////////////////
        // СТБ 34.101
        ////////////////////////////////////////////////////////////////////////////
        public static void TestSTB34101(CAPI.Factory factory, Container container) 
        {
            WriteLine("STB34101");
        
            // закодировать параметры алгоритма хэширования
            ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_hash), ASN1.Null.Instance
            ); 
            // закодировать параметры алгоритма подписи
            ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_bign_hbelt), ASN1.Null.Instance
            );
            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_keyWrap_256), ASN1.Null.Instance
            );
            // закодировать параметры алгоритма 
            ASN1.ISO.AlgorithmIdentifier transportParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_bign_keyTransport), wrapParameters
            );
            if (container != null)
            {
                // указать алгоритм хэширования
                using (CAPI.Hash hashAlgorithm = container.Provider.CreateAlgorithm<CAPI.Hash>(
                    container.Store, hashParameters))
                {
                    // получить алгоритм выработки подписи
                    using (SignHash signHash = container.Provider.CreateAlgorithm<SignHash>(
                        container.Store, signHashParameters))
                    try {
                        // выполнить тест
                        Sign.STB34101.SignHash.Test(factory, container, signHash, hashAlgorithm);
                    }
                    // удалить ключи из контейнера
                    finally { container.DeleteKeys(); }

                    // вывести сообщение
                    Write("OK  ");

                    // получить алгоритм проверки подписи
                    using (VerifyHash verifyHash = container.Provider.CreateAlgorithm<VerifyHash>(
                        container.Store, signHashParameters))
                    {
                        // выполнить тест
                        Sign.STB34101.VerifyHash.Test(verifyHash, hashAlgorithm);
                    }
                    // вывести сообщение
                    Write("OK  ");
                
                    // указать алгоритм зашифрования ключа
                    using (TransportKeyWrap wrapAlgorithm = 
                        container.Provider.CreateAlgorithm<TransportKeyWrap>(
                            container.Store, transportParameters))
                    {
                        // выполнить тест
                        Keyx.STB34101.TransportKeyWrap.Test(wrapAlgorithm);
                    }
                    // вывести сообщение
                    Write("OK  ");
                
                    // указать алгоритм расшифрования ключа
                    using (TransportKeyUnwrap unwrapAlgorithm = 
                        container.Provider.CreateAlgorithm<TransportKeyUnwrap>(
                            container.Store, transportParameters))
                    try {
                        // выполнить тест
                        Keyx.STB34101.TransportKeyUnwrap.Test(
                            factory, container, unwrapAlgorithm
                        );
                    }
                    // удалить ключи из контейнера
                    finally { container.DeleteKeys(); }
                
                    // вывести сообщение
                    Write("OK  ");
                }
            }
            else {
                // указать алгоритм хэширования
                using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                    null, hashParameters))
                {
                    // получить алгоритм выработки подписи
                    using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                        null, signHashParameters))
                    {
                        // выполнить тест
                        Sign.STB34101.SignHash.Test(factory, container, signHash, hashAlgorithm);
                    }
                    // вывести сообщение
                    Write("OK  ");
                
                    // получить алгоритм проверки подписи
                    using (VerifyHash verifyHash = factory.CreateAlgorithm<VerifyHash>(
                        null, signHashParameters))
                    {
                        // выполнить тест
                        Sign.STB34101.VerifyHash.Test(verifyHash, hashAlgorithm);
                    }
                    // вывести сообщение
                    Write("OK  ");
                
                    // указать алгоритм зашифрования ключа
                    using (TransportKeyWrap wrapAlgorithm = 
                        factory.CreateAlgorithm<TransportKeyWrap>(null, transportParameters))
                    {
                        // выполнить тест
                        Keyx.STB34101.TransportKeyWrap.Test(wrapAlgorithm);
                    }
                    // указать алгоритм расшифрования ключа
                    using (TransportKeyUnwrap unwrapAlgorithm = 
                        factory.CreateAlgorithm<TransportKeyUnwrap>(null, transportParameters))
                    {
                        // выполнить тест
                        Keyx.STB34101.TransportKeyUnwrap.Test(factory, container, unwrapAlgorithm);
                    }
                    // вывести сообщение
                    Write("OK  ");
                }
            }
            WriteLine();
        }
        public static void TestSTB34101(CAPI.Factory factory, SecurityObject scope, 
            IRand rand, bool generate, KeyFlags keyFlags, String paramOID) 
        {
            WriteLine("STB34101/{0}", paramOID);
        
            // указать идентификатор ключа
            string keyOID = ASN1.STB.OID.stb34101_bign_pubKey; int[] keySizes = new int[] {16, 24, 32}; 
        
            // указать доверенную фабрику
            using (Factory trustFactory = new STB.Factory()) 
            {
                // получить фабрику кодирования
                KeyFactory keyFactory = trustFactory.GetKeyFactory(keyOID); 

                // указать способ использования ключа
                KeyUsage keyUsage = keyFactory.GetKeyUsage(); 
        
                // раскодировать параметры алгоритма
                IParameters parameters = keyFactory.DecodeParameters(
                    new ASN1.ObjectIdentifier(paramOID)
                ); 
                // сгенерировать ключевую пару
                using (KeyPair keyPair = GenerateKeyPair(
                    factory, scope, rand, trustFactory, null, generate, 
                    keyOID, parameters, keyUsage, keyFlags)) 
                try {
                    // при допустимости использования ключа
                    if ((keyUsage & KeyUsage.DigitalSignature) != KeyUsage.None)
                    {
                        // закодировать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_hash), ASN1.Null.Instance
                        ); 
                        // закодировать параметры алгоритма подписи
                        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_bign_hbelt), ASN1.Null.Instance
                        );
                        // закодировать параметры алгоритма подписи
                        ASN1.ISO.AlgorithmIdentifier signParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_bign_hbelt), null
                        );
                        // выполнить тест
                        SignTest(trustFactory, null, hashParameters, 
                            signHashParameters, signParameters, keyPair, keyFlags
                        );
                    }
                    if ((keyUsage & KeyUsage.KeyEncipherment) != KeyUsage.None)
                    {
                        // указать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier transportParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_bign_keyTransport), ASN1.Null.Instance
                        ); 
                        // выполнить тест
                        TransportKeyTest(trustFactory, null, 
                            transportParameters, keyPair, keyFlags, keySizes
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

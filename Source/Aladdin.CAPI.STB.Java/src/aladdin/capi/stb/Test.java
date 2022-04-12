package aladdin.capi.stb;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.stb.*;
import aladdin.capi.*;
import aladdin.capi.Factory;

public final class Test extends aladdin.capi.Test
{
    public static void main(String[] parameters) throws Exception
    {
        try (Factory factory = new aladdin.capi.stb.Factory()) 
        {
            SecurityStore scope = null; 
            
            ////////////////////////////////////////////////////////////////////
            // Симметричные алгоритмы
            ////////////////////////////////////////////////////////////////////
            testHash_STB11761  (factory, scope); 
            testHash_STB34101  (factory, scope); 
            testMAC_STB34101   (factory, scope);
            testCipher_STB34101(factory, scope);
            testKDF_STB34101   (factory, scope);
            testWrapSTB34101   (factory, scope);

            // указать генератор случайных данных
            try (IRand rand = new aladdin.capi.Rand(null))
            {
                ////////////////////////////////////////////////////////////////////
                // СТБ 1176.2
                ////////////////////////////////////////////////////////////////////
                testSTB11762_BDS(factory, scope, rand, 
                    true, KeyFlags.NONE, OID.STB11762_PARAMS3_BDS
                );
                testSTB11762_BDS(factory, scope, rand,
                    true, KeyFlags.NONE, OID.STB11762_PARAMS6_BDS
                );
                testSTB11762_BDS(factory, scope, rand,
                    true, KeyFlags.NONE, OID.STB11762_PARAMS10_BDS
                );
                testSTB11762_BDSPRO(factory, scope, rand,
                    true, KeyFlags.NONE, OID.STB11762_PARAMS3_BDS
                );
                testSTB11762_BDSPRO(factory, scope, rand,
                    true, KeyFlags.NONE, OID.STB11762_PARAMS6_BDS
                );
                testSTB11762_BDSPRO(factory, scope, rand,
                    true, KeyFlags.NONE, OID.STB11762_PARAMS10_BDS
                );
                testSTB11762_BDS_BDH(factory, scope, rand,
                    true, KeyFlags.NONE, OID.STB11762_PARAMS3
                );
                testSTB11762_BDS_BDH(factory, scope, rand,
                    true, KeyFlags.NONE, OID.STB11762_PARAMS6
                );
                testSTB11762_BDS_BDH(factory, scope, rand,
                    true, KeyFlags.NONE, OID.STB11762_PARAMS10
                );
                testSTB11762_BDSPRO_BDH(factory, scope, rand,
                    true, KeyFlags.NONE, OID.STB11762_PARAMS3
                );
                testSTB11762_BDSPRO_BDH(factory, scope, rand,
                    true, KeyFlags.NONE, OID.STB11762_PARAMS6
                );
                testSTB11762_BDSPRO_BDH(factory, scope, rand,
                    true, KeyFlags.NONE, OID.STB11762_PARAMS10
                );
                ////////////////////////////////////////////////////////////////////
                // СТБ 34.101
                ////////////////////////////////////////////////////////////////////
                testSTB34101(factory, null);
                testSTB34101(factory, scope, rand,
                    true, KeyFlags.NONE, OID.STB34101_BIGN_CURVE256_V1
                );
                testSTB34101(factory, scope, rand,
                    true, KeyFlags.NONE, OID.STB34101_BIGN_CURVE384_V1
                );
                testSTB34101(factory, scope, rand,
                    true, KeyFlags.NONE, OID.STB34101_BIGN_CURVE512_V1
                );
            }
        }
        catch (Throwable e) { e.printStackTrace(System.err); throw e; }
    }
	///////////////////////////////////////////////////////////////////////////
	// Алгоритмы хэширования
	///////////////////////////////////////////////////////////////////////////
    public static void testHash_STB11761(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.STB11761");
        
		// указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.STB11761_HASH0), Null.INSTANCE
        ); 
        // создать алгоритм хэширования
        try (Hash algorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class)) 
        {
            // выполнить тест
            aladdin.capi.stb.hash.STB11761.test(algorithm);
        }
    }
    public static void testHash_STB34101(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.STB34101");
            
		// указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.STB34101_BELT_HASH), Null.INSTANCE
        ); 
        // создать алгоритм хэширования
        try (Hash algorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class)) 
        {
            // выполнить тест
            aladdin.capi.stb.hash.STB34101.test(algorithm);
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Алгоритмы вычисления имитовставки
    ////////////////////////////////////////////////////////////////////////////
    public static void testMAC_STB34101(Factory factory, SecurityStore scope) throws Exception
    {
        println("MAC.STB34101");
            
		// указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.STB34101_BELT_MAC_256), Null.INSTANCE
        ); 
        // создать алгоритм выработки имитовставки
        try (Mac algorithm = (Mac)factory.createAlgorithm(scope, parameters, Mac.class))
        {
            // выполнить тест
            aladdin.capi.stb.mac.STB34101.test(algorithm);
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Алгоритмы шифрования
    ////////////////////////////////////////////////////////////////////////////
    public static void testCipher_STB34101(Factory factory, SecurityStore scope) throws Exception
    {
        println("Cipher.STB34101");
        
        // создать алгоритм шифрования
        try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
            scope, "STB34101", Null.INSTANCE, IBlockCipher.class))
        {
            // выполнить тест
            aladdin.capi.stb.engine.STB34101.test(blockCipher);
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Алгоритмы наследования ключа
    ////////////////////////////////////////////////////////////////////////////
    public static void testKDF_STB34101(Factory factory, SecurityStore scope) throws Exception
    {
        println("KeyDerive.STB34101");
            
		// указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.STB34101_BELT_KEYPREP), 
            new OctetString(new byte[] {
                (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
            })
        ); 
        // создать алгоритм наследования ключа
        try (KeyDerive algorithm = (KeyDerive)factory.createAlgorithm(
            scope, parameters, KeyDerive.class)) 
        {
            // выполнить тест
            aladdin.capi.stb.derive.STB34101.test1(algorithm);
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Алгоритмы шифрования ключа
    ////////////////////////////////////////////////////////////////////////////
    public static void testWrapSTB34101(Factory factory, SecurityStore scope) throws Exception
    {
        println("KeyWrap.STB34101");
        
		// указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.STB34101_BELT_KEYWRAP_256), Null.INSTANCE
        );
        // создать алгоритм шифрования ключа
        try (KeyWrap algorithm = (KeyWrap)factory.createAlgorithm(scope, parameters, KeyWrap.class)) 
        {
            // выполнить тест
            aladdin.capi.stb.wrap.STB34101.test(algorithm);
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // СТБ 1176.2
    ////////////////////////////////////////////////////////////////////////////
    public static void testSTB11762_BDS(Factory factory, SecurityObject scope, 
        IRand rand, boolean generate, KeyFlags keyFlags, String paramOID) throws Exception
    {
        println("STB11762.BDS/%1$s", paramOID);
        
        // указать идентификатор ключа
        String keyOID = OID.STB11762_BDS_PUBKEY; 
        
        // указать способ использования ключа
        KeyUsage keyUsage = new KeyUsage(KeyUsage.DIGITAL_SIGNATURE); 
        
        // указать доверенную фабрику
        try (Factory trustFactory = new aladdin.capi.stb.Factory()) 
        {
            // закодировать параметры ключа
            IEncodable encodedParameters = new Explicit<ObjectIdentifier>(
                ObjectIdentifier.class, Tag.context(0), 
                new ObjectIdentifier(paramOID)
            ); 
            // получить фабрику кодирования
            KeyFactory keyFactory = trustFactory.getKeyFactory(keyOID); 

            // раскодировать параметры алгоритма
            IParameters parameters = keyFactory.decodeParameters(encodedParameters); 

            // сгенерировать ключевую пару
            try (KeyPair keyPair = generateKeyPair(
                factory, scope, rand, trustFactory, null, generate, 
                keyOID, parameters, keyUsage, keyFlags))
            {
                // закодировать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.STB11761_HASHA), Null.INSTANCE
                ); 
                // закодировать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.STB11762_SIGN), Null.INSTANCE
                );
                // закодировать параметры алгоритма подписи
                AlgorithmIdentifier signParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.STB11762_SIGN), null
                );
                // выполнить тест
                signTest(trustFactory, null, hashParameters, 
                    signHashParameters, signParameters, keyPair, keyFlags
                );
            }
            // удалить ключи контейнера
            finally { deleteKeys(scope); }
        }
        println();        
    }
    public static void testSTB11762_BDSPRO(Factory factory, SecurityObject scope, 
        IRand rand, boolean generate, KeyFlags keyFlags, String paramOID) throws Exception
    {
        println("STB11762.BDSPRO/%1$s", paramOID);
        
        // указать идентификатор ключа
        String keyOID = OID.STB11762_PRE_BDS_PUBKEY; 
        
        // указать способ использования ключа
        KeyUsage keyUsage = new KeyUsage(KeyUsage.DIGITAL_SIGNATURE); 
        
        // указать доверенную фабрику
        try (Factory trustFactory = new aladdin.capi.stb.Factory()) 
        {
            // закодировать параметры ключа
            IEncodable encodedParameters = new Explicit<ObjectIdentifier>(
                ObjectIdentifier.class, Tag.context(0), 
                new ObjectIdentifier(paramOID)
            ); 
            // получить фабрику кодирования
            KeyFactory keyFactory = trustFactory.getKeyFactory(keyOID); 

            // раскодировать параметры алгоритма
            IParameters parameters = keyFactory.decodeParameters(encodedParameters); 

            // сгенерировать ключевую пару
            try (KeyPair keyPair = generateKeyPair(
                factory, scope, rand, trustFactory, null, generate, 
                keyOID, parameters, keyUsage, keyFlags))
            {
                // закодировать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.STB11761_HASHA), Null.INSTANCE
                ); 
                // закодировать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.STB11762_SIGN), Null.INSTANCE
                );
                // закодировать параметры алгоритма подписи
                AlgorithmIdentifier signParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.STB11762_PRE_SIGN), null
                );
                // выполнить тест
                signTest(trustFactory, null, hashParameters, 
                    signHashParameters, signParameters, keyPair, keyFlags
                );
            }
            // удалить ключи контейнера
            finally { deleteKeys(scope); }
        }
        println();        
    }
    public static void testSTB11762_BDS_BDH(Factory factory, SecurityObject scope, 
        IRand rand, boolean generate, KeyFlags keyFlags, String paramOID) throws Exception
    {
        println("STB11762.BDS_BDH/%1$s", paramOID);
        
        // указать идентификатор ключа
        String keyOID = OID.STB11762_BDSBDH_PUBKEY; int[] keySizes = new int[] {32}; 
        
        // указать доверенную фабрику
        try (Factory trustFactory = new aladdin.capi.stb.Factory()) 
        {
            // получить фабрику кодирования ключей
            KeyFactory keyFactory = trustFactory.getKeyFactory(keyOID); 

            // указать способ использования ключа
            KeyUsage keyUsage = keyFactory.getKeyUsage(); 

            // закодировать параметры ключа
            IEncodable encodedParameters = new Explicit<ObjectIdentifier>(
                ObjectIdentifier.class, Tag.context(2), 
                new ObjectIdentifier(paramOID)
            ); 
            // раскодировать параметры алгоритма
            IParameters parameters = keyFactory.decodeParameters(encodedParameters); 

            // сгенерировать ключевую пару
            try (KeyPair keyPair = generateKeyPair(
                factory, scope, rand, trustFactory, null, generate, 
                keyOID, parameters, keyUsage, keyFlags)) 
            {
                // при допустимости использования ключа
                if (keyUsage.contains(KeyUsage.DIGITAL_SIGNATURE))
                {
                    // закодировать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB11761_HASHA), Null.INSTANCE
                    ); 
                    // закодировать параметры алгоритма подписи
                    AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB11762_SIGN), Null.INSTANCE
                    );
                    // закодировать параметры алгоритма подписи
                    AlgorithmIdentifier signParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB11762_SIGN), null
                    );
                    // выполнить тест
                    signTest(trustFactory, null, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags
                    );
                }
                // при допустимости использования ключа
                if (keyUsage.contains(KeyUsage.KEY_ENCIPHERMENT))
                {
                    // указать параметры алгоритма
                    AlgorithmIdentifier transportParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB11762_BDH_KEYTRANS), Null.INSTANCE
                    ); 
                    // выполнить тест
                    transportKeyTest(trustFactory, null, 
                        transportParameters, keyPair, keyFlags, keySizes
                    );
                }
            }
            // удалить ключи контейнера
            finally { deleteKeys(scope); }
        }
        println();        
    }
    public static void testSTB11762_BDSPRO_BDH(Factory factory, SecurityObject scope, 
        IRand rand, boolean generate, KeyFlags keyFlags, String paramOID) throws Exception
    {
        println("STB11762.BDSPRO_BDH/%1$s", paramOID);
        
        // указать идентификатор ключа
        String keyOID = OID.STB11762_PRE_BDSBDH_PUBKEY; int[] keySizes = new int[] {32}; 
        
        // указать доверенную фабрику
        try (Factory trustFactory = new aladdin.capi.stb.Factory()) 
        {
            // получить фабрику кодирования ключей
            KeyFactory keyFactory = trustFactory.getKeyFactory(keyOID); 

            // указать способ использования ключа
            KeyUsage keyUsage = keyFactory.getKeyUsage(); 

            // закодировать параметры ключа
            IEncodable encodedParameters = new Explicit<ObjectIdentifier>(
                ObjectIdentifier.class, Tag.context(2), 
                new ObjectIdentifier(paramOID)
            ); 
            // раскодировать параметры алгоритма
            IParameters parameters = keyFactory.decodeParameters(encodedParameters); 
            
            // сгенерировать ключевую пару
            try (KeyPair keyPair = generateKeyPair(
                factory, scope, rand, trustFactory, null, generate, 
                keyOID, parameters, keyUsage, keyFlags)) 
            {
                // при допустимости использования ключа
                if (keyUsage.contains(KeyUsage.DIGITAL_SIGNATURE))
                {
                    // закодировать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB11761_HASHA), Null.INSTANCE
                    ); 
                    // закодировать параметры алгоритма подписи
                    AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB11762_SIGN), Null.INSTANCE
                    );
                    // закодировать параметры алгоритма подписи
                    AlgorithmIdentifier signParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB11762_PRE_SIGN), null
                    );
                    // выполнить тест
                    signTest(trustFactory, null, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags
                    );
                }
                // при допустимости использования ключа
                if (keyUsage.contains(KeyUsage.KEY_ENCIPHERMENT))
                {
                    // указать параметры алгоритма
                    AlgorithmIdentifier transportParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB11762_BDH_KEYTRANS), Null.INSTANCE
                    ); 
                    // выполнить тест
                    transportKeyTest(trustFactory, null, 
                        transportParameters, keyPair, keyFlags, keySizes
                    );
                }
            }
            // удалить ключи контейнера
            finally { deleteKeys(scope); }
        }
        println();        
    }
    ////////////////////////////////////////////////////////////////////////////
    // СТБ 34.101
    ////////////////////////////////////////////////////////////////////////////
    public static void testSTB34101(Factory factory, Container container) throws Exception
    {
        println("STB34101");
        
        // закодировать параметры алгоритма хэширования
        AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.stb.OID.STB34101_BELT_HASH), Null.INSTANCE
        ); 
        // закодировать параметры алгоритма подписи
        AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.stb.OID.STB34101_BIGN_HBELT), Null.INSTANCE
        );
        // указать параметры алгоритма
        AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.STB34101_BELT_KEYWRAP_256), Null.INSTANCE
        );
        // закодировать параметры алгоритма 
        AlgorithmIdentifier transportParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.stb.OID.STB34101_BIGN_KEYTRANSPORT), 
            wrapParameters
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
                    aladdin.capi.stb.sign.stb34101.SignHash.test(
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
                    aladdin.capi.stb.sign.stb34101.VerifyHash.test(
                        verifyHash, hashAlgorithm
                    );
                }
                // вывести сообщение
                print("OK  ");
                
                // указать алгоритм зашифрования ключа
                try (TransportKeyWrap wrapAlgorithm = (TransportKeyWrap)
                    container.provider().createAlgorithm(
                        container.store(), transportParameters, TransportKeyWrap.class))
                {
                    // выполнить тест
                    aladdin.capi.stb.keyx.stb34101.TransportKeyWrap.test(wrapAlgorithm);
                }
                // вывести сообщение
                print("OK  ");
                
                // указать алгоритм расшифрования ключа
                try (TransportKeyUnwrap unwrapAlgorithm = (TransportKeyUnwrap)
                    container.provider().createAlgorithm(
                        container.store(), transportParameters, TransportKeyUnwrap.class))
                {
                    // выполнить тест
                    aladdin.capi.stb.keyx.stb34101.TransportKeyUnwrap.test(
                        factory, container, unwrapAlgorithm
                    );
                }
                // удалить ключи из контейнера
                finally { container.deleteKeys(); }
                
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
                    aladdin.capi.stb.sign.stb34101.SignHash.test(
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
                    aladdin.capi.stb.sign.stb34101.VerifyHash.test(
                        verifyHash, hashAlgorithm
                    );
                }
                // вывести сообщение
                print("OK  ");
                
                // указать алгоритм зашифрования ключа
                try (TransportKeyWrap wrapAlgorithm = (TransportKeyWrap)
                    factory.createAlgorithm(null, transportParameters, TransportKeyWrap.class))
                {
                    // выполнить тест
                    aladdin.capi.stb.keyx.stb34101.TransportKeyWrap.test(wrapAlgorithm);
                }
                // указать алгоритм расшифрования ключа
                try (TransportKeyUnwrap unwrapAlgorithm = (TransportKeyUnwrap)
                    factory.createAlgorithm(null, transportParameters, TransportKeyUnwrap.class))
                {
                    // выполнить тест
                    aladdin.capi.stb.keyx.stb34101.TransportKeyUnwrap.test(
                        factory, container, unwrapAlgorithm
                    );
                }
                // вывести сообщение
                print("OK  ");
            }
        }
        println();        
    }
    public static void testSTB34101(Factory factory, SecurityObject scope, 
        IRand rand, boolean generate, KeyFlags keyFlags, String paramOID) throws Exception
    {
        println("STB34101/%1$s", paramOID);
        
        // указать идентификатор ключа
        String keyOID = OID.STB34101_BIGN_PUBKEY; int[] keySizes = new int[] {16, 24, 32}; 
        
        // указать доверенную фабрику
        try (Factory trustFactory = new aladdin.capi.stb.Factory()) 
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
                // при допустимости использования ключа
                if (keyUsage.contains(KeyUsage.DIGITAL_SIGNATURE))
                {
                    // закодировать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BELT_HASH), Null.INSTANCE
                    ); 
                    // закодировать параметры алгоритма подписи
                    AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BIGN_HBELT), Null.INSTANCE
                    );
                    // закодировать параметры алгоритма подписи
                    AlgorithmIdentifier signParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BIGN_HBELT), null
                    );
                    // выполнить тест
                    signTest(trustFactory, null, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags
                    );
                }
                if (keyUsage.contains(KeyUsage.KEY_ENCIPHERMENT))
                {
                    // указать параметры алгоритма
                    AlgorithmIdentifier transportParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BIGN_KEYTRANSPORT), Null.INSTANCE
                    ); 
                    // выполнить тест
                    transportKeyTest(trustFactory, null, 
                        transportParameters, keyPair, keyFlags, keySizes
                    );
                }
            }
            // удалить ключи контейнера
            finally { deleteKeys(scope); }
        }
        println();        
    }
}

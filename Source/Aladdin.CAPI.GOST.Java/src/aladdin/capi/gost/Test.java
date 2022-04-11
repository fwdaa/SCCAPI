package aladdin.capi.gost;
import aladdin.*;
import aladdin.math.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import aladdin.asn1.gost.OID;
import aladdin.asn1.iso.pkcs.*;
import aladdin.asn1.iso.pkcs.pkcs7.*;
import aladdin.asn1.iso.pkcs.pkcs8.*;
import aladdin.asn1.iso.pkcs.pkcs12.*;
import aladdin.capi.*;
import aladdin.capi.Factory;
import aladdin.capi.Container;
import aladdin.capi.CipherMode;
import aladdin.capi.pkcs12.*;
import java.math.*;
import java.security.spec.*;
import java.io.*;
import java.util.*;

public class Test extends aladdin.capi.Test
{
    public static void main(String[] parameters) throws Exception
    {
        try (aladdin.capi.gost.Factory factory = new aladdin.capi.gost.Factory()) 
        {
            SecurityStore scope = null; 
            
            CMS.test(factory);             
            
            // идентификаторы наборов параметров
            String[] hashOIDs = new String[] {
                OID.HASHES_TEST, OID.HASHES_CRYPTOPRO
            }; 
            // идентификаторы наборов параметров
            String[] sboxOIDs = new String[] {
                OID.ENCRYPTS_TEST, OID.ENCRYPTS_A,
                OID.ENCRYPTS_B,    OID.ENCRYPTS_C,     
                OID.ENCRYPTS_D,    OID.ENCRYPTS_TC26_Z
            }; 
            /////////////////////////////////////////////////////////////////////
            // Алгоритмы хэширования
            ////////////////////////////////////////////////////////////////////
            for (int i = 0; i < hashOIDs.length; i++)
            {
                testGOSTR3411_1994(factory, scope, hashOIDs[i]); 
            }
            testGOSTR3411_2012_256(factory, scope); 
            testGOSTR3411_2012_512(factory, scope); 
            
            /////////////////////////////////////////////////////////////////////
            // Алгоритмы вычисления имитовставки
            ////////////////////////////////////////////////////////////////////
            for (int i = 0; i < sboxOIDs.length; i++)
            {
                testMAC_GOST28147(factory, scope, sboxOIDs[i]); 
            }
            for (int i = 0; i < hashOIDs.length; i++)
            {
                testHMAC_GOSTR3411_1994(factory, scope, hashOIDs[i]); 
            }
            testHMAC_GOSTR3411_2012_256(factory, scope); 
            testHMAC_GOSTR3411_2012_512(factory, scope); 
            testMAC_GOSTR3412          (factory, scope);
        
            /////////////////////////////////////////////////////////////////////
            // Алгоритмы шифрования
            ////////////////////////////////////////////////////////////////////
            for (int i = 0; i < sboxOIDs.length; i++)
            {
                testGOST28147(factory, scope, sboxOIDs[i]);                     
            }
            testGOSTR3412(factory, scope); 
            
            /////////////////////////////////////////////////////////////////////
            // Алгоритмы наследования ключа
            ////////////////////////////////////////////////////////////////////
            testPBKDF2_HMAC_GOST3411_94(factory, scope); 
            testKDF_GOSTR3411_2012     (factory, scope); 
        
            // указать генератор случайных данных
            try (IRand rand = new aladdin.capi.Rand(null))
            {
                /////////////////////////////////////////////////////////////////////
                // ГОСТ Р 34.10
                ////////////////////////////////////////////////////////////////////
                int wrapFlags = 
                    aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_A | 
                    aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_B | 
                    aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_C | 
                    aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_D |
                    aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_A | 
                    aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_B | 
                    aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_C | 
                    aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_D; 

                testGOSTR3410_1994(factory, null); 
                testGOSTR3410_1994(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.EXCHANGES_A, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_A, wrapFlags
                ); 
                testGOSTR3410_1994(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.EXCHANGES_A, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_B, wrapFlags
                ); 
                testGOSTR3410_1994(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.EXCHANGES_A, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_C, wrapFlags
                ); 
                testGOSTR3410_1994(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.EXCHANGES_A, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_D, wrapFlags
                ); 
                testGOSTR3410_1994(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.EXCHANGES_B, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_A, wrapFlags
                ); 
                testGOSTR3410_1994(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.EXCHANGES_B, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_B, wrapFlags
                ); 
                testGOSTR3410_1994(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.EXCHANGES_B, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_C, wrapFlags
                ); 
                testGOSTR3410_1994(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.EXCHANGES_B, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_D, wrapFlags
                ); 
                testGOSTR3410_1994(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.EXCHANGES_C, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_A, wrapFlags
                ); 
                testGOSTR3410_1994(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.EXCHANGES_C, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_B, wrapFlags
                ); 
                testGOSTR3410_1994(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.EXCHANGES_C, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_C, wrapFlags
                ); 
                testGOSTR3410_1994(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.EXCHANGES_C, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_D, wrapFlags
                ); 

                testGOSTR3410_2001(factory, null); 
                testGOSTR3410_2001(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.ECC_SIGNS_A, OID.HASHES_CRYPTOPRO, null, 0
                ); 
                testGOSTR3410_2001(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.ECC_SIGNS_B, OID.HASHES_CRYPTOPRO, null, 0
                ); 
                testGOSTR3410_2001(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.ECC_SIGNS_C, OID.HASHES_CRYPTOPRO, null, 0
                ); 
                testGOSTR3410_2001(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.ECC_EXCHANGES_A, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_A, wrapFlags 
                ); 
                testGOSTR3410_2001(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.ECC_EXCHANGES_A, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_B, wrapFlags 
                ); 
                testGOSTR3410_2001(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.ECC_EXCHANGES_A, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_C, wrapFlags 
                ); 
                testGOSTR3410_2001(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.ECC_EXCHANGES_A, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_D, wrapFlags 
                ); 
                testGOSTR3410_2001(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.ECC_EXCHANGES_B, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_A, wrapFlags
                ); 
                testGOSTR3410_2001(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.ECC_EXCHANGES_B, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_B, wrapFlags
                ); 
                testGOSTR3410_2001(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.ECC_EXCHANGES_B, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_C, wrapFlags
                ); 
                testGOSTR3410_2001(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.ECC_EXCHANGES_B, OID.HASHES_CRYPTOPRO, OID.ENCRYPTS_D, wrapFlags
                ); 

                int[] keySizes = new int[] {32, 64}; 
                wrapFlags = wrapFlags | 
                    aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_Z | 
                    aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_Z; 

                testGOSTR3410_2012_256(factory, null); 
                testGOSTR3410_2012_256(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.ECC_SIGNS_A, null, 0
                ); 
                testGOSTR3410_2012_256(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.ECC_SIGNS_B, null, 0
                ); 
                testGOSTR3410_2012_256(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.ECC_SIGNS_C, null, 0
                ); 
                testGOSTR3410_2012_256(factory, scope, rand, true, KeyFlags.NONE, 
                    OID.ECC_EXCHANGES_A, keySizes, wrapFlags
                ); 
                testGOSTR3410_2012_256(factory, scope, rand, true, KeyFlags.NONE,
                    OID.ECC_EXCHANGES_B, keySizes, wrapFlags
                ); 
                testGOSTR3410_2012_256(factory, scope, rand, true, KeyFlags.NONE,
                    OID.ECC_TC26_2012_256A, keySizes, wrapFlags
                ); 

                testGOSTR3410_2012_512(factory, null, keySizes); 
                testGOSTR3410_2012_512(factory, scope, rand, true, KeyFlags.NONE,
                    OID.ECC_TC26_2012_512A, keySizes, wrapFlags
                ); 
                testGOSTR3410_2012_512(factory, scope, rand, true, KeyFlags.NONE,
                    OID.ECC_TC26_2012_512B, keySizes, wrapFlags
                ); 
                testGOSTR3410_2012_512(factory, scope, rand, true, KeyFlags.NONE,
                    OID.ECC_TC26_2012_512C, keySizes, wrapFlags
                ); 
            }
            /////////////////////////////////////////////////////////////////////
            // CMS/PKCS12
            ////////////////////////////////////////////////////////////////////
            CMS   .test(factory); 
            PKCS12.test(factory);
        }
        catch (Throwable e) { e.printStackTrace(System.err); throw e; }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Алгоритмы хэширования
    ////////////////////////////////////////////////////////////////////////////
    public static void testGOSTR3411_1994(
        Factory factory, SecurityStore scope, String hashOID) throws Exception
    {
        println("Hash.GOSTR3411_1994/%1$s", hashOID);
        
		// указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3411_94), new ObjectIdentifier(hashOID)
        ); 
        // создать алгоритм хэширования
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class)) 
        {
            if (hashOID.equals(OID.HASHES_TEST))
            {
                // выполнить тест
                aladdin.capi.gost.hash.GOSTR3411_1994.testTest(hashAlgorithm);
            }
            if (hashOID.equals(OID.HASHES_CRYPTOPRO))
            {
                // выполнить тест
                aladdin.capi.gost.hash.GOSTR3411_1994.testPro(hashAlgorithm);
            }
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.gost.Factory()) 
            {
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    public static void testGOSTR3411_2012_256(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.GOSTR3411_2012_256");
        
		// указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3411_2012_256), Null.INSTANCE
        ); 
        // создать алгоритм хэширования
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class)) 
        {
            // выполнить тест
            aladdin.capi.gost.hash.GOSTR3411_2012.test256(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.gost.Factory()) 
            {
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    public static void testGOSTR3411_2012_512(Factory factory, SecurityStore scope) throws Exception
    {
        println("Hash.GOSTR3411_2012_512");
        
		// указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3411_2012_512), Null.INSTANCE
        ); 
        // создать алгоритм хэширования
        try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(scope, parameters, Hash.class)) 
        {
            // выполнить тест
            aladdin.capi.gost.hash.GOSTR3411_2012.test512(hashAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.gost.Factory()) 
            {
                // протестировать алгоритм
                hashTest(hashAlgorithm, trustFactory, null, parameters); 
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Алгоритмы вычисления имитовставки
    ////////////////////////////////////////////////////////////////////////////
    public static void testMAC_GOST28147(Factory factory, 
        SecurityStore scope, String sboxOID) throws Exception
    {
        println("MAC.GOST28147/%1$s", sboxOID);

		// указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOST28147_89_MAC), 
            new GOST28147CipherParameters(
                new OctetString(new byte[8]), new ObjectIdentifier(sboxOID)
            )
        ); 
        // создать алгоритм вычисления имитовставки
        try (Mac macAlgorithm = (Mac)factory.createAlgorithm(scope, parameters, Mac.class))
        { 
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.gost.Factory()) 
            {
                // указать допустимые размеры
                int[] dataSizes = new int[] { 0, 1, 7, 8, 9, 15, 16, 17, 1023, 1024, 1025 }; 
                
                // выполнить тест
                macTest(macAlgorithm, trustFactory, null, parameters, dataSizes); 
            }
        }
    }
    public static void testHMAC_GOSTR3411_1994(
        Factory factory, SecurityStore scope, String hashOID) throws Exception
    {
        println("MAC.HMAC_GOSTR3411_1994/%1$s", hashOID);

        // указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3411_94_HMAC), new ObjectIdentifier(hashOID)
        ); 
        // создать алгоритм вычисления имитовставки
        try (Mac macAlgorithm = (Mac)factory.createAlgorithm(scope, parameters, Mac.class))
        {
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.gost.Factory()) 
            {
                // указать допустимые размеры
                int[] dataSizes = new int[] { 0, 1, 31, 32, 33 }; 
                
                // выполнить тест
                macTest(macAlgorithm, trustFactory, null, parameters, dataSizes); 
            }
        }
    }
    public static void testHMAC_GOSTR3411_2012_256(
        Factory factory, SecurityStore scope) throws Exception
    {
        println("MAC.HMAC_GOSTR3411_2012_256");

        // указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3411_2012_HMAC_256), Null.INSTANCE
        ); 
        // создать алгоритм вычисления имитовставки
        try (Mac macAlgorithm = (Mac)factory.createAlgorithm(scope, parameters, Mac.class))
        {
            // выполнить тест
            aladdin.capi.gost.hash.GOSTR3411_2012.testHMAC256(macAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.gost.Factory()) 
            {
                // указать допустимые размеры
                int[] dataSizes = new int[] { 0, 1, 63, 64, 65 }; 
                
                // выполнить тест
                macTest(macAlgorithm, trustFactory, null, parameters, dataSizes); 
            }
        }
    }    
    public static void testHMAC_GOSTR3411_2012_512(
        Factory factory, SecurityStore scope) throws Exception
    {
        println("MAC.HMAC_GOSTR3411_2012_512");
        
		// указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3411_2012_HMAC_512), Null.INSTANCE
        ); 
        // создать алгоритм вычисления имитовставки
        try (Mac macAlgorithm = (Mac)factory.createAlgorithm(scope, parameters, Mac.class)) 
        {
            // выполнить тест
            aladdin.capi.gost.hash.GOSTR3411_2012.testHMAC512(macAlgorithm);
            
            // указать доверенную фабрику
            try (Factory trustFactory = new aladdin.capi.gost.Factory()) 
            {
                // указать допустимые размеры
                int[] dataSizes = new int[] { 0, 1, 63, 64, 65 }; 
                
                // выполнить тест
                macTest(macAlgorithm, trustFactory, null, parameters, dataSizes); 
            }
        }
    }    
    public static void testMAC_GOSTR3412(
        Factory factory, SecurityStore scope) throws Exception
    {
        println("MAC.GOSTR3412/64");

        // создать алгоритм шифрования блока
        try (IBlockCipher blockCipher = factory.createBlockCipher(
            scope, "GOST3412_2015_M", Null.INSTANCE))
        {
            // выполнить тест
            aladdin.capi.gost.engine.GOSTR3412_K.testMAC64(blockCipher);
        }
        println(); 
        println("MAC.GOSTR3412/128");
        
        // создать алгоритм шифрования блока
        try (IBlockCipher blockCipher = factory.createBlockCipher(
            scope, "GOST3412_2015_K", Null.INSTANCE))
        {
            // выполнить тест
            aladdin.capi.gost.engine.GOSTR3412_K.testMAC128(blockCipher);
        }
        println(); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Алгоритмы шифрования
    ////////////////////////////////////////////////////////////////////////////
    public static void testGOST28147(IBlockCipher blockCipher, String paramOID) throws Exception
    {
        // указать допустимые размеры
        int[] dataSizes = new int[] { 0, 1, 7, 8, 9, 15, 16, 17, 1023, 1024, 1025 }; 
        
        // указать доверенную фабрику
        try (aladdin.capi.gost.Factory trustFactory = new aladdin.capi.gost.Factory()) 
        {
            // указать генератор случайных данных
            try (IRand rand = new aladdin.capi.Rand(null))
            {
                // указать параметры алгоритма
                IEncodable paramSet = new ObjectIdentifier(paramOID); 
        
                // получить доверенный алгоритм шифрования
                try (IBlockCipher trustBlockCipher = trustFactory.createBlockCipher(
                    null, "GOST28147", paramSet))
                {
                    // указать режим ECB
                    CipherMode parameters = new CipherMode.ECB(); 

                    // создать режим шифрования
                    try (Cipher trustCipher = trustBlockCipher.createBlockMode(parameters))
                    {
                        // создать режим шифрования
                        try (Cipher cipher = blockCipher.createBlockMode(parameters))
                        {
                            // для специального случая
                            if (paramOID.equals(OID.ENCRYPTS_TC26_Z)) 
                            {
                                // выполнить тест
                                aladdin.capi.gost.engine.GOST28147.testZ(cipher);
                            }
                            // выполнить тест
                            Cipher.compatibleTest(rand, cipher, 
                                trustCipher, PaddingMode.PKCS5, dataSizes); 
                        }
                    }
                    // сгенерировать синхропосылку
                    byte[] iv = new byte[8]; generate(iv, 0, iv.length); 
                    
                    // указать режим CBC
                    parameters = new CipherMode.CBC(iv); 

                    // создать режим шифрования
                    try (Cipher trustCipher = trustBlockCipher.createBlockMode(parameters))
                    {
                        // создать режим шифрования
                        try (Cipher cipher = blockCipher.createBlockMode(parameters))
                        {
                            // выполнить тест
                            Cipher.compatibleTest(rand, cipher, trustCipher, 
                                PaddingMode.PKCS5, dataSizes
                            ); 
                        }
                    }
                    // указать режим CTR
                    rand.generate(iv, 0, iv.length); parameters = new CipherMode.CTR(iv, iv.length); 

                    // создать режим шифрования
                    try (Cipher trustCipher = trustBlockCipher.createBlockMode(parameters))
                    {
                        // создать режим шифрования
                        try (Cipher cipher = blockCipher.createBlockMode(parameters))
                        {
                            // выполнить тест
                            Cipher.compatibleTest(rand, cipher, 
                                trustCipher, PaddingMode.NONE, dataSizes
                            ); 
                        }
                    }
                    // указать режим CFB
                    rand.generate(iv, 0, iv.length); parameters = new CipherMode.CFB(iv, iv.length); 

                    // создать режим шифрования
                    try (Cipher trustCipher = trustBlockCipher.createBlockMode(parameters))
                    {
                        // создать режим шифрования
                        try (Cipher cipher = blockCipher.createBlockMode(parameters))
                        {
                            // выполнить тест
                            Cipher.compatibleTest(rand, cipher, 
                                trustCipher, PaddingMode.NONE, dataSizes
                            ); 
                        }
                    }
                }
            }
        }
    }
    public static void testGOST28147(Factory factory, 
        SecurityStore scope, String paramOID) throws Exception
    {
        println("Cipher.GOST28147/%1$s", paramOID);
        
        // указать параметры алгоритма
        IEncodable paramSet = new ObjectIdentifier(paramOID); 
                
        // создать блочный алгоритм шифрования
        try (IBlockCipher blockCipher = factory.createBlockCipher(scope, "GOST28147", paramSet))
        {
            // выполнить тесты
            if (blockCipher != null) testGOST28147(blockCipher, paramOID); 
        }
        // указать допустимые размеры
        int[] dataSizes = new int[] { 0, 1, 7, 8, 9, 15, 16, 17, 1023, 1024, 1025 }; 

        // сгенерировать синхропосылку
        byte[] iv = new byte[8]; generate(iv, 0, iv.length); 

        // указать параметры алгоритма
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOST28147_89), new GOST28147CipherParameters(
                new OctetString(iv), new ObjectIdentifier(paramOID)
            )
        ); 
        // создать алгоритм шифрования
        try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class))
        {
            // указать доверенную фабрику
            try (aladdin.capi.gost.Factory trustFactory = new aladdin.capi.gost.Factory()) 
            {
                // выполнить тест
                cipherTest(cipher, PaddingMode.NONE, trustFactory, null, parameters, dataSizes);
            }
        }
    }
    public static void testGOSTR3412(Factory factory, SecurityStore scope) throws Exception
    {
        println("Cipher.GOSTR3412/64");
        
        // создать алгоритм шифрования блока
        try (IBlockCipher blockCipher = factory.createBlockCipher(
            scope, "GOST3412_2015_M", Null.INSTANCE))
        {
            // протестировать алгоритм
            aladdin.capi.gost.engine.GOSTR3412_K.test64(blockCipher);
        }
        println();
        println("Cipher.GOSTR3412/128");
        
        // создать алгоритм шифрования блока
        try (IBlockCipher blockCipher = factory.createBlockCipher(
            scope, "GOST3412_2015_K", Null.INSTANCE))
        {
            // протестировать алгоритм
            aladdin.capi.gost.engine.GOSTR3412_K.test128(blockCipher);
        }
        println();

        // протестировать алгоритм
        println("KeyWrap.KExp15/64");
        aladdin.capi.gost.wrap.KExp15.test(factory, scope, 8);
        println();
        
        println("KeyWrap.KExp15/128");
        aladdin.capi.gost.wrap.KExp15.test(factory, scope, 16);
        println();
    }
    ////////////////////////////////////////////////////////////////////////////
    // Алгоритмы наследования ключа
    ////////////////////////////////////////////////////////////////////////////
    public static void testPBKDF2_HMAC_GOST3411_94(
        Factory factory, SecurityStore scope) throws Exception
    {
        println("KeyDerive.PBKDF2_GOST3411_94");
        
        // выполнить тест
        aladdin.capi.gost.hash.GOSTR3411_1994.testPBKDF2(factory, scope);
    }
    public static void testKDF_GOSTR3411_2012(
        Factory factory, SecurityStore scope) throws Exception
    {
        println("KeyDerive.KDF_GOSTR3411_2012");
        
		// указать параметры алгоритма
		AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3411_2012_HMAC_256), Null.INSTANCE
        ); 
        // создать алгоритм вычисления имитовставки
        try (Mac macAlgorithm = (Mac)factory.createAlgorithm(scope, parameters, Mac.class)) 
        {
            // выполнить тест
            aladdin.capi.gost.derive.TC026.test(macAlgorithm);
        }
    }    
    ////////////////////////////////////////////////////////////////////////////
    // ГОСТ P 34.10
    ////////////////////////////////////////////////////////////////////////////
    public static void testGOSTR3410_1994(Factory factory, Container container) throws Exception
    {
        println("GOSTR3410.1994");
        
        // закодировать параметры алгоритма подписи
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3410_1994), Null.INSTANCE
        );
        if (container != null)
        {
            // получить алгоритм выработки подписи
            try (SignHash signHash = (SignHash)container.provider().createAlgorithm(
                container.store(), parameters, SignHash.class))
            {
                // выполнить тест
                aladdin.capi.gost.sign.gostr3410.DHSignHash.test(
                    factory, container, signHash
                );
            }
            // удалить ключи из контейнера
            finally { container.deleteKeys(); }

            // вывести сообщение
            print("OK  ");

            // получить алгоритм проверки подписи
            try (VerifyHash verifyHash = (VerifyHash)container.provider().createAlgorithm(
                container.store(), parameters, VerifyHash.class))
            {
                // выполнить тест
                aladdin.capi.gost.sign.gostr3410.DHVerifyHash.test(verifyHash);
            }
            // вывести сообщение
            print("OK  ");
        }
        else {
            // получить алгоритм выработки подписи
            try (SignHash signHash = (SignHash)factory.createAlgorithm(
                null, parameters, SignHash.class))
            {
                // выполнить тест
                aladdin.capi.gost.sign.gostr3410.DHSignHash.test(
                    factory, container, signHash
                );
            }
            // вывести сообщение
            print("OK  ");
            
            // получить алгоритм проверки подписи
            try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                null, parameters, VerifyHash.class))
            {
                // выполнить тест
                aladdin.capi.gost.sign.gostr3410.DHVerifyHash.test(verifyHash);
            }
            // вывести сообщение
            print("OK  ");
        }
        println();
    }
    public static void testGOSTR3410_1994(Factory factory, SecurityObject scope, 
        IRand rand, boolean generate, KeyFlags keyFlags, String paramOID, 
        String hashOID, String sboxOID, int wrapFlags) throws Exception
    {
        // сформировать заголовок
        String header = String.format("%1$s/%2$s", paramOID, hashOID); 
        
        // сформировать заголовок
        if (sboxOID != null) header = String.format("%1$s/%2$s", header, sboxOID); 
        
        // вывести заголовок
        println("GOSTR3410.1994/%1$s", header);
        
        // указать идентификатор ключа
        String keyOID = OID.GOSTR3410_1994; int[] keySizes = new int[] {32};
        
        // указать доверенную фабрику
        try (Factory trustFactory = new aladdin.capi.gost.Factory()) 
        {
            // получить фабрику кодирования ключей
            KeyFactory keyFactory = trustFactory.getKeyFactory(keyOID); 

            // указать способ использования ключа
            KeyUsage keyUsage = keyFactory.getKeyUsage(); 
            
            // скорректировать способ использования ключа
            if (wrapFlags == 0) keyUsage = new KeyUsage(keyUsage.value() & 
                ~(KeyUsage.KEY_ENCIPHERMENT | KeyUsage.KEY_AGREEMENT)
            ); 
            // скорректировать способ использования ключа
            else keyUsage = new KeyUsage(keyUsage.value() & ~KeyUsage.DIGITAL_SIGNATURE); 

            // в зависимости от параметров
            ObjectIdentifier encodedSBoxOID = null; if (sboxOID != null) 
            { 
                // закодировать таблицу подстановок
                encodedSBoxOID = new ObjectIdentifier(sboxOID); 
            }
            // закодировать параметры ключа
            IEncodable encodedParameters = new GOSTR3410PublicKeyParameters2001(
                new ObjectIdentifier(paramOID), 
                new ObjectIdentifier(hashOID), encodedSBoxOID
            ); 
            // раскодировать параметры алгоритма
            IParameters parameters = keyFactory.decodeParameters(encodedParameters); 

            // сгенерировать ключевую пару
            try (KeyPair keyPair = generateKeyPair(
                factory, scope, rand, trustFactory, null, generate, 
                keyOID, parameters, keyUsage, keyFlags)) 
            {
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.DIGITAL_SIGNATURE))
                { 
                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_94), 
                        new ObjectIdentifier(hashOID) 
                    ); 
                    // указать параметры алгоритма
                    AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(keyOID), Null.INSTANCE
                    ); 
                    // указать параметры алгоритма
                    AlgorithmIdentifier signParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_94_R3410_1994), null
                    ); 
                    // выполнить тест
                    signTest(trustFactory, null, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags 
                    );
                }
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.KEY_ENCIPHERMENT))
                { 
                    // указать параметры алгоритма
                    AlgorithmIdentifier transportParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(keyOID), Null.INSTANCE
                    ); 
                    // выполнить тест
                    transportKeyTest(trustFactory, null, 
                        transportParameters, keyPair, keyFlags, keySizes
                    );
                }
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.KEY_AGREEMENT))
                { 
                    // выполнить тест
                    testAgreementGOSTR3410(trustFactory, null, keyPair, keyFlags,  
                        OID.GOSTR3410_1994_SSDH, keySizes, wrapFlags
                    );
                    // выполнить тест
                    testAgreementGOSTR3410(trustFactory, null, keyPair, keyFlags,  
                        OID.GOSTR3410_1994_ESDH, keySizes, wrapFlags
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
    public static void testGOSTR3410_2001(Factory factory, Container container) throws Exception
    {
        println("GOSTR3410.2001");
        
        // указать идентификатор ключа и параметров хэширования
        String keyOID = OID.GOSTR3410_2001; String hashOID = OID.HASHES_TEST; 
        
        // закодировать параметры алгоритма подписи
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(keyOID), Null.INSTANCE
        );
        if (container != null)
        {
            // получить алгоритм выработки подписи
            try (SignHash signHash = (SignHash)container.provider().createAlgorithm(
                container.store(), parameters, SignHash.class))
            {
                // выполнить тест
                aladdin.capi.gost.sign.gostr3410.ECSignHash.test256(
                    factory, container, signHash, keyOID, hashOID
                );
            }
            // удалить ключи из контейнера
            finally { container.deleteKeys(); }
            
            // вывести сообщение
            print("OK  ");
            
            // получить алгоритм проверки подписи
            try (VerifyHash verifyHash = (VerifyHash)container.provider().createAlgorithm(
                container.store(), parameters, VerifyHash.class))
            {
                // выполнить тест
                aladdin.capi.gost.sign.gostr3410.ECVerifyHash.test256(
                    verifyHash, keyOID, hashOID
                );
            }
            // вывести сообщение
            print("OK  ");
        }
        else {
            // получить алгоритм выработки подписи
            try (SignHash signHash = (SignHash)factory.createAlgorithm(
                null, parameters, SignHash.class))
            {
                // выполнить тест
                aladdin.capi.gost.sign.gostr3410.ECSignHash.test256(
                    factory, container, signHash, keyOID, hashOID
                );
            }
            // вывести сообщение
            print("OK  ");
            
            // получить алгоритм проверки подписи
            try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                null, parameters, VerifyHash.class))
            {
                // выполнить тест
                aladdin.capi.gost.sign.gostr3410.ECVerifyHash.test256(
                    verifyHash, keyOID, hashOID
                );
            }
            // вывести сообщение
            print("OK  ");
        }
        println();
    }
    public static void testGOSTR3410_2001(Factory factory, SecurityObject scope, 
        IRand rand, boolean generate, KeyFlags keyFlags, String paramOID, 
        String hashOID, String sboxOID, int wrapFlags) throws Exception
    {
        // сформировать заголовок
        String header = String.format("%1$s/%2$s", paramOID, hashOID); 
        
        // сформировать заголовок
        if (sboxOID != null) header = String.format("%1$s/%2$s", header, sboxOID); 
        
        // вывести заголовок
        println("GOSTR3410.2001/%1$s", header);
        
        // указать идентификатор ключа
        String keyOID = OID.GOSTR3410_2001; int[] keySizes = new int[] {32};
        
        // указать доверенную фабрику
        try (Factory trustFactory = new aladdin.capi.gost.Factory()) 
        {
            // получить фабрику кодирования ключей
            KeyFactory keyFactory = trustFactory.getKeyFactory(keyOID); 

            // указать способ использования ключа
            KeyUsage keyUsage = keyFactory.getKeyUsage(); 

            // скорректировать способ использования ключа
            if (wrapFlags == 0) keyUsage = new KeyUsage(keyUsage.value() & 
                ~(KeyUsage.KEY_ENCIPHERMENT | KeyUsage.KEY_AGREEMENT)
            ); 
            // скорректировать способ использования ключа
            else keyUsage = new KeyUsage(keyUsage.value() & ~KeyUsage.DIGITAL_SIGNATURE); 
            
            // в зависимости от параметров
            ObjectIdentifier encodedSBoxOID = null; if (sboxOID != null) 
            {
                // закодировать таблицу подстановок
                encodedSBoxOID = new ObjectIdentifier(sboxOID); 
            }
            // закодировать параметры ключа
            IEncodable encodedParameters = new GOSTR3410PublicKeyParameters2001(
                new ObjectIdentifier(paramOID), 
                new ObjectIdentifier(hashOID), encodedSBoxOID
            ); 
            // раскодировать параметры алгоритма
            IParameters parameters = keyFactory.decodeParameters(encodedParameters); 

            // сгенерировать ключевую пару
            try (KeyPair keyPair = generateKeyPair(
                factory, scope, rand, trustFactory, null, generate, 
                keyOID, parameters, keyUsage, keyFlags)) 
            {
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.DIGITAL_SIGNATURE))
                { 
                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_94), 
                        new ObjectIdentifier(hashOID) 
                    ); 
                    // указать параметры алгоритма
                    AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(keyOID), Null.INSTANCE
                    ); 
                    // указать параметры алгоритма
                    AlgorithmIdentifier signParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_94_R3410_2001), null
                    ); 
                    // выполнить тест
                    signTest(trustFactory, null, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags 
                    );
                }
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.KEY_ENCIPHERMENT))
                { 
                    // указать параметры алгоритма
                    AlgorithmIdentifier transportParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(keyOID), Null.INSTANCE
                    ); 
                    // выполнить тест
                    transportKeyTest(trustFactory, null, 
                        transportParameters, keyPair, keyFlags, keySizes
                    );
                }
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.KEY_AGREEMENT))
                { 
                    // выполнить тест
                    testAgreementGOSTR3410(trustFactory, null, keyPair, keyFlags, 
                        OID.GOSTR3410_2001_SSDH, keySizes, wrapFlags
                    );
                    // выполнить тест
                    testAgreementGOSTR3410(trustFactory, null, keyPair, keyFlags,  
                        OID.GOSTR3410_2001_ESDH, keySizes, wrapFlags
                    );
                }
            }
            // удалить ключи контейнера
            finally { deleteKeys(scope); }
        }
        println();
    }
    ////////////////////////////////////////////////////////////////////////////
    // ГОСТ P 34.10-2012-256
    ////////////////////////////////////////////////////////////////////////////
    public static void testGOSTR3410_2012_256(Factory factory, Container container) throws Exception
    {
        println("GOSTR3410.2012/256");
        
        // указать идентификатор ключа и алгоритма хэширования
        String keyOID = OID.GOSTR3410_2012_256; String hashOID = OID.GOSTR3411_2012_256; 
        
        // закодировать параметры алгоритма подписи
        AlgorithmIdentifier parameters = new AlgorithmIdentifier(
            new ObjectIdentifier(keyOID), Null.INSTANCE
        );
        if (container != null)
        {
            // получить алгоритм выработки подписи
            try (SignHash signHash = (SignHash)container.provider().createAlgorithm(
                container.store(), parameters, SignHash.class))
            {
                // выполнить тест
                aladdin.capi.gost.sign.gostr3410.ECSignHash.test256(
                    factory, container, signHash, keyOID, hashOID
                );
            }
            // удалить ключи из контейнера
            finally { container.deleteKeys(); }
            
            // вывести сообщение
            print("OK  ");
            
            // получить алгоритм проверки подписи
            try (VerifyHash verifyHash = (VerifyHash)container.provider().createAlgorithm(
                container.store(), parameters, VerifyHash.class))
            {
                // выполнить тест
                aladdin.capi.gost.sign.gostr3410.ECVerifyHash.test256(
                    verifyHash, keyOID, hashOID
                );
            }
            // вывести сообщение
            print("OK  ");
        }
        else {
            // получить алгоритм выработки подписи
            try (SignHash signHash = (SignHash)factory.createAlgorithm(
                null, parameters, SignHash.class))
            {
                // выполнить тест
                aladdin.capi.gost.sign.gostr3410.ECSignHash.test256(
                    factory, container, signHash, keyOID, hashOID
                );
            }
            // вывести сообщение
            print("OK  ");
            
            // получить алгоритм проверки подписи
            try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                null, parameters, VerifyHash.class))
            {
                // выполнить тест
                aladdin.capi.gost.sign.gostr3410.ECVerifyHash.test256(
                    verifyHash, keyOID, hashOID
                );
            }
            // вывести сообщение
            print("OK  ");
        }
        println();
    }
    public static void testGOSTR3410_2012_256(Factory factory, SecurityObject scope, 
        IRand rand, boolean generate, KeyFlags keyFlags, 
        String paramOID, int[] keySizes, int wrapFlags) throws Exception 
    {
        // сформировать заголовок
        String header = String.format("%1$s", paramOID); 
        
        // вывести заголовок
        println("GOSTR3410.2012/256/%1$s", header);
        
        // указать идентификатор ключа
        String keyOID = OID.GOSTR3410_2012_256; String hashOID = OID.GOSTR3411_2012_256; 
        
        // указать доверенную фабрику
        try (Factory trustFactory = new aladdin.capi.gost.Factory()) 
        {
            // получить фабрику кодирования ключей
            KeyFactory keyFactory = trustFactory.getKeyFactory(keyOID); 

            // указать способ использования ключа
            KeyUsage keyUsage = keyFactory.getKeyUsage(); 

            // скорректировать способ использования ключа
            if (wrapFlags == 0) keyUsage = new KeyUsage(keyUsage.value() & 
                ~(KeyUsage.KEY_ENCIPHERMENT | KeyUsage.KEY_AGREEMENT)
            ); 
            else { 
                // в зависимости от идентификатора
                if (!paramOID.equals(aladdin.asn1.gost.OID.ECC_TC26_2012_256A))
                { 
                    // скорректировать способ использования ключа
                    keyUsage = new KeyUsage(keyUsage.value() & ~KeyUsage.DIGITAL_SIGNATURE); 
                }
            }
            // закодировать параметры ключа
            IEncodable encodedParameters = new GOSTR3410PublicKeyParameters2012(
                new ObjectIdentifier(paramOID), new ObjectIdentifier(hashOID)
            ); 
            // раскодировать параметры алгоритма
            IParameters parameters = keyFactory.decodeParameters(encodedParameters); 

            // сгенерировать ключевую пару
            try (KeyPair keyPair = generateKeyPair(
                factory, scope, rand, trustFactory, null, generate, 
                keyOID, parameters, keyUsage, keyFlags)) 
            {
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.DIGITAL_SIGNATURE))
                { 
                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(hashOID), Null.INSTANCE
                    ); 
                    // указать параметры алгоритма
                    AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(keyOID), Null.INSTANCE
                    ); 
                    // указать параметры алгоритма
                    AlgorithmIdentifier signParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_2012_R3410_2012_256), null
                    ); 
                    // выполнить тест
                    signTest(trustFactory, null, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags 
                    );
                }
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.KEY_ENCIPHERMENT))
                { 
                    // указать параметры алгоритма
                    AlgorithmIdentifier transportParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(keyOID), Null.INSTANCE
                    ); 
                    // для всех размеров
                    for (int keySize : keySizes)
                    {
                        // выполнить тест
                        transportKeyTest(trustFactory, null, 
                            transportParameters, keyPair, keyFlags, keySize
                        );
                    }
                }
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.KEY_AGREEMENT))
                { 
                    // выполнить тесты
                    testAgreementGOSTR3410(trustFactory, null, keyPair, keyFlags,  
                        OID.GOSTR3410_2012_DH_256, keySizes, wrapFlags
                    ); 
                }
            }
            // удалить ключи контейнера
            finally { deleteKeys(scope); }
        }
        println();
    }
    ////////////////////////////////////////////////////////////////////////////
    // ГОСТ P 34.10-2012-512
    ////////////////////////////////////////////////////////////////////////////
    public static void testGOSTR3410_2012_512(
        Factory factory, Container container, int[] keySizes) throws Exception
    {
        println("GOSTR3410.2012/512");
        
        // закодировать параметры алгоритма подписи
        AlgorithmIdentifier signParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3410_2012_512), Null.INSTANCE
        );
        // закодировать параметры алгоритма согласования
        AlgorithmIdentifier agreementParameters = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.GOSTR3410_2012_DH_512), Null.INSTANCE
        );
        if (container != null)
        {
            // получить алгоритм выработки подписи
            try (SignHash signHash = (SignHash)container.provider().createAlgorithm(
                container.store(), signParameters, SignHash.class))
            {
                // выполнить тест
                aladdin.capi.gost.sign.gostr3410.ECSignHash.test512(
                    factory, container, signHash
                );
            }
            // удалить ключи из контейнера
            finally { container.deleteKeys(); }

            // вывести сообщение
            print("OK  ");
            
            // получить алгоритм проверки подписи
            try (VerifyHash verifyHash = (VerifyHash)container.provider().createAlgorithm(
                container.store(), signParameters, VerifyHash.class))
            {
                // выполнить тест
                aladdin.capi.gost.sign.gostr3410.ECVerifyHash.test512(verifyHash);
            }
            // вывести сообщение
            print("OK  ");
            
            // получить алгоритм согласования ключа
            try (IKeyAgreement agreement = (IKeyAgreement)container.provider().createAlgorithm(
                container.store(), agreementParameters, IKeyAgreement.class))
            {
                // выполнить тест
                aladdin.capi.gost.keyx.gostr3410.ECKeyAgreement2012.test(
                    factory, container, agreement, keySizes
                );
            }
            // удалить ключи из контейнера
            finally { container.deleteKeys(); }
            
            // вывести сообщение
            print("OK  ");
        }
        else {
            // получить алгоритм выработки подписи
            try (SignHash signHash = (SignHash)factory.createAlgorithm(
                null, signParameters, SignHash.class))
            {
                // выполнить тест
                aladdin.capi.gost.sign.gostr3410.ECSignHash.test512(
                    factory, container, signHash
                );
            }
            // вывести сообщение
            print("OK  ");
            
            // получить алгоритм проверки подписи
            try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                null, signParameters, VerifyHash.class))
            {
                // выполнить тест
                aladdin.capi.gost.sign.gostr3410.ECVerifyHash.test512(verifyHash);
            }
            // вывести сообщение
            print("OK  ");
            
            // получить алгоритм согласования ключа
            try (IKeyAgreement agreement = (IKeyAgreement)factory.createAlgorithm(
                null, agreementParameters, IKeyAgreement.class))
            {
                // выполнить тест
                aladdin.capi.gost.keyx.gostr3410.ECKeyAgreement2012.test(
                    factory, container, agreement, keySizes
                );
            }
            // вывести сообщение
            print("OK  ");
        }
        println();
    }
    public static void testGOSTR3410_2012_512(Factory factory, SecurityObject scope, 
        IRand rand, boolean generate, KeyFlags keyFlags, 
        String paramOID, int[] keySizes, int wrapFlags) throws Exception 
    {
        // сформировать заголовок
        String header = String.format("%1$s", paramOID); 
        
        // вывести заголовок
        println("GOSTR3410.2012/512/%1$s", header);
        
        // указать идентификатор ключа
        String keyOID = OID.GOSTR3410_2012_512; String hashOID = OID.GOSTR3411_2012_512; 
        
        // указать доверенную фабрику
        try (Factory trustFactory = new aladdin.capi.gost.Factory()) 
        {
            // получить фабрику кодирования ключей
            KeyFactory keyFactory = trustFactory.getKeyFactory(keyOID); 

            // указать способ использования ключа
            KeyUsage keyUsage = keyFactory.getKeyUsage(); 

            // скорректировать способ использования ключа
            if (wrapFlags == 0) keyUsage = new KeyUsage(keyUsage.value() & 
                ~(KeyUsage.KEY_ENCIPHERMENT | KeyUsage.KEY_AGREEMENT)
            ); 
            // закодировать параметры ключа
            IEncodable encodedParameters = new GOSTR3410PublicKeyParameters2012(
                new ObjectIdentifier(paramOID), new ObjectIdentifier(hashOID)
            ); 
            // раскодировать параметры алгоритма
            IParameters parameters = keyFactory.decodeParameters(encodedParameters); 

            // сгенерировать ключевую пару
            try (KeyPair keyPair = generateKeyPair(
                factory, scope, rand, trustFactory, null, generate, 
                keyOID, parameters, keyUsage, keyFlags)) 
            {
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.DIGITAL_SIGNATURE))
                { 
                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(hashOID), Null.INSTANCE
                    ); 
                    // указать параметры алгоритма
                    AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(keyOID), Null.INSTANCE
                    ); 
                    // указать параметры алгоритма
                    AlgorithmIdentifier signParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_2012_R3410_2012_512), null
                    ); 
                    // выполнить тест
                    signTest(trustFactory, null, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags 
                    );
                }
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.KEY_ENCIPHERMENT))
                { 
                    // указать параметры алгоритма
                    AlgorithmIdentifier transportParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(keyOID), Null.INSTANCE
                    ); 
                    // для всех размеров
                    for (int keySize : keySizes)
                    {
                        // выполнить тест
                        transportKeyTest(trustFactory, null, 
                            transportParameters, keyPair, keyFlags, keySize
                        );
                    }
                }
                // при допустимости теста
                if (keyUsage.contains(KeyUsage.KEY_AGREEMENT))
                { 
                    // выполнить тест
                    testAgreementGOSTR3410(trustFactory, null, keyPair, keyFlags,  
                        OID.GOSTR3410_2012_DH_256, keySizes, wrapFlags
                    ); 
                }
            }
            // удалить ключи контейнера
            finally { deleteKeys(scope); }
        }
        println();
    }
    ////////////////////////////////////////////////////////////////////////////
    // Обмен ключами ГОСТ P 34.10
    ////////////////////////////////////////////////////////////////////////////
    public static void testAgreementGOSTR3410(Factory factory, SecurityStore scope, 
        KeyPair keyPair, KeyFlags keyFlags, String agreementOID, 
        int[] keySizes, int wrapFlags) throws Exception
    {
        if ((wrapFlags & aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_A) != 0)
        {
            // сгенерировать случайные данные
            byte[] ukm = new byte[8]; generate(ukm, 0, ukm.length); 

            // закодировать параметры алгоритма 
            AlgorithmIdentifier keyAgreementParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(keyPair.publicKey.keyOID()), Null.INSTANCE
            ); 
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.KEY_WRAP_NONE), 
                new KeyWrapParameters(
                    new ObjectIdentifier(OID.ENCRYPTS_A), new OctetString(ukm)
                )
            ); 
            // закодировать параметры алгоритма 
            AlgorithmIdentifier esdhParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(agreementOID), wrapParameters
            ); 
            // выполнить тест
            testAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                keyAgreementParameters, esdhParameters, keySizes 
            ); 
        }
        if ((wrapFlags & aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_B) != 0)
        {
            // сгенерировать случайные данные
            byte[] ukm = new byte[8]; generate(ukm, 0, ukm.length); 

            // закодировать параметры алгоритма 
            AlgorithmIdentifier keyAgreementParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(keyPair.publicKey.keyOID()), Null.INSTANCE
            ); 
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.KEY_WRAP_NONE), 
                new KeyWrapParameters(
                    new ObjectIdentifier(OID.ENCRYPTS_B), new OctetString(ukm)
                )
            ); 
            // закодировать параметры алгоритма 
            AlgorithmIdentifier esdhParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(agreementOID), wrapParameters
            ); 
            // выполнить тест
            testAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                keyAgreementParameters, esdhParameters, keySizes 
            ); 
        }
        if ((wrapFlags & aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_C) != 0)
        {
            // сгенерировать случайные данные
            byte[] ukm = new byte[8]; generate(ukm, 0, ukm.length); 

            // закодировать параметры алгоритма 
            AlgorithmIdentifier keyAgreementParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(keyPair.publicKey.keyOID()), Null.INSTANCE
            ); 
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.KEY_WRAP_NONE), 
                new KeyWrapParameters(
                    new ObjectIdentifier(OID.ENCRYPTS_C), new OctetString(ukm)
                )
            ); 
            // закодировать параметры алгоритма 
            AlgorithmIdentifier esdhParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(agreementOID), wrapParameters
            ); 
            // выполнить тест
            testAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                keyAgreementParameters, esdhParameters, keySizes 
            ); 
        }
        if ((wrapFlags & aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_D) != 0)
        {
            // сгенерировать случайные данные
            byte[] ukm = new byte[8]; generate(ukm, 0, ukm.length); 

            // закодировать параметры алгоритма 
            AlgorithmIdentifier keyAgreementParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(keyPair.publicKey.keyOID()), Null.INSTANCE
            ); 
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.KEY_WRAP_NONE), 
                new KeyWrapParameters(
                    new ObjectIdentifier(OID.ENCRYPTS_D), new OctetString(ukm)
                )
            ); 
            // закодировать параметры алгоритма 
            AlgorithmIdentifier esdhParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(agreementOID), wrapParameters
            ); 
            // выполнить тест
            testAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                keyAgreementParameters, esdhParameters, keySizes 
            ); 
        }
        if ((wrapFlags & aladdin.capi.gost.wrap.RFC4357.NONE_SBOX_Z) != 0)
        {
            // сгенерировать случайные данные
            byte[] ukm = new byte[8]; generate(ukm, 0, ukm.length); 

            // закодировать параметры алгоритма 
            AlgorithmIdentifier keyAgreementParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(keyPair.publicKey.keyOID()), Null.INSTANCE
            ); 
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.KEY_WRAP_NONE), 
                new KeyWrapParameters(
                    new ObjectIdentifier(OID.ENCRYPTS_TC26_Z), new OctetString(ukm)
                )
            ); 
            // закодировать параметры алгоритма 
            AlgorithmIdentifier esdhParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(agreementOID), wrapParameters
            ); 
            // выполнить тест
            testAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                keyAgreementParameters, esdhParameters, keySizes 
            ); 
        }
        if ((wrapFlags & aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_A) != 0)
        {
            // сгенерировать случайные данные
            byte[] ukm = new byte[8]; generate(ukm, 0, ukm.length); 

            // закодировать параметры алгоритма 
            AlgorithmIdentifier keyAgreementParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(keyPair.publicKey.keyOID()), Null.INSTANCE
            ); 
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.KEY_WRAP_CRYPTOPRO), 
                new KeyWrapParameters(
                    new ObjectIdentifier(OID.ENCRYPTS_A), new OctetString(ukm)
                )
            ); 
            // закодировать параметры алгоритма 
            AlgorithmIdentifier esdhParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(agreementOID), wrapParameters
            ); 
            // выполнить тест
            testAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                keyAgreementParameters, esdhParameters, keySizes 
            ); 
        }
        if ((wrapFlags & aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_B) != 0)
        {
            // сгенерировать случайные данные
            byte[] ukm = new byte[8]; generate(ukm, 0, ukm.length); 

            // закодировать параметры алгоритма 
            AlgorithmIdentifier keyAgreementParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(keyPair.publicKey.keyOID()), Null.INSTANCE
            ); 
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.KEY_WRAP_CRYPTOPRO), 
                new KeyWrapParameters(
                    new ObjectIdentifier(OID.ENCRYPTS_B), new OctetString(ukm)
                )
            ); 
            // закодировать параметры алгоритма 
            AlgorithmIdentifier esdhParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(agreementOID), wrapParameters
            ); 
            // выполнить тест
            testAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                keyAgreementParameters, esdhParameters, keySizes 
            ); 
        }
        if ((wrapFlags & aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_C) != 0)
        {
            // сгенерировать случайные данные
            byte[] ukm = new byte[8]; generate(ukm, 0, ukm.length); 

            // закодировать параметры алгоритма 
            AlgorithmIdentifier keyAgreementParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(keyPair.publicKey.keyOID()), Null.INSTANCE
            ); 
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.KEY_WRAP_CRYPTOPRO), 
                new KeyWrapParameters(
                    new ObjectIdentifier(OID.ENCRYPTS_C), new OctetString(ukm)
                )
            ); 
            // закодировать параметры алгоритма 
            AlgorithmIdentifier esdhParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(agreementOID), wrapParameters
            ); 
            // выполнить тест
            testAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                keyAgreementParameters, esdhParameters, keySizes 
            ); 
        }
        if ((wrapFlags & aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_D) != 0)
        {
            // сгенерировать случайные данные
            byte[] ukm = new byte[8]; generate(ukm, 0, ukm.length); 

            // закодировать параметры алгоритма 
            AlgorithmIdentifier keyAgreementParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(keyPair.publicKey.keyOID()), Null.INSTANCE
            ); 
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.KEY_WRAP_CRYPTOPRO), 
                new KeyWrapParameters(
                    new ObjectIdentifier(OID.ENCRYPTS_D), new OctetString(ukm)
                )
            ); 
            // закодировать параметры алгоритма 
            AlgorithmIdentifier esdhParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(agreementOID), wrapParameters
            ); 
            // выполнить тест
            testAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                keyAgreementParameters, esdhParameters, keySizes 
            ); 
        }
        if ((wrapFlags & aladdin.capi.gost.wrap.RFC4357.CPRO_SBOX_Z) != 0)
        {
            // сгенерировать случайные данные
            byte[] ukm = new byte[8]; generate(ukm, 0, ukm.length); 

            // закодировать параметры алгоритма 
            AlgorithmIdentifier keyAgreementParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(keyPair.publicKey.keyOID()), Null.INSTANCE
            ); 
            // закодировать параметры алгоритма шифрования ключа
            AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.KEY_WRAP_CRYPTOPRO), 
                new KeyWrapParameters(
                    new ObjectIdentifier(OID.ENCRYPTS_TC26_Z), new OctetString(ukm)
                )
            ); 
            // закодировать параметры алгоритма 
            AlgorithmIdentifier esdhParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(agreementOID), wrapParameters
            ); 
            // выполнить тест
            testAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                keyAgreementParameters, esdhParameters, keySizes 
            ); 
        }
    }
    public static void testAgreementGOSTR3410(Factory factory, SecurityStore scope, 
        KeyPair keyPair, KeyFlags keyFlags, AlgorithmIdentifier keyAgreementParameters, 
        AlgorithmIdentifier esdhParameters, int[] keySizes) throws Exception
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
                // для всех размеров
                if (keyAgreementParameters != null) for (int keySize : keySizes)
                {
                    // выполнить тест
                    keyAgreementTest(factory, scope, keyAgreementParameters,
                        keyPair, keyFlags, ephemeralKeyPair, keySize
                    );
                }
                // для всех размеров
                if (esdhParameters != null) for (int keySize : keySizes)
                {
                    // выполнить тест
                    transportAgreementTest(factory, scope, esdhParameters,
                        keyPair, keyFlags, ephemeralKeyPair, keySize
                    );
                }
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // ГОСТ CMS
    ////////////////////////////////////////////////////////////////////////////
    public static final class CMS extends RefObject
    {
        // личный ключ и сертификат открытого ключа
        private final IPrivateKey privateKey; private final Certificate certificate;
        // сертификат открытого ключа другой стороны
        private final Certificate otherCertificate;

        // конструктор
        public CMS(Factory factory, String certificateBase64, byte[] encodedPrivateKey, 
            String otherCertificateBase64, String caCertificateBase64) throws Exception
        {
            // открытый ключ и параметры ключа
            aladdin.capi.gost.gostr3410.ECPublicKey   publicKey   = null; 
            aladdin.capi.gost.gostr3410.IECParameters parameters  = null; 
            
            Certificate certificateCA = null; if (caCertificateBase64 != null) 
            {
                // получить закодированный сертификат
                byte[] encodedCertificate = Base64.getDecoder().decode(caCertificateBase64);

                // раскодировать сертификат
                certificateCA = new Certificate(encodedCertificate); 
            }
            if (otherCertificateBase64 == null) otherCertificate = null; 
            else {
                // получить закодированный сертификат
                byte[] encodedCertificate = Base64.getDecoder().decode(otherCertificateBase64);

                // раскодировать сертификат
                otherCertificate = new Certificate(encodedCertificate); 
                
                // проверить подпись сертификата
                if (certificateCA != null) PKI.verifyCertificate(
                    factory, null, otherCertificate, certificateCA
                );
                
                // извлечь открытый ключ
                publicKey = (aladdin.capi.gost.gostr3410.ECPublicKey)
                    otherCertificate.getPublicKey(factory); 

                // указать параметры ключа
                parameters = (aladdin.capi.gost.gostr3410.IECParameters)
                    publicKey.parameters(); 
                
                // проверить принадлежность точки кривой
                if (!parameters.getCurve().isPoint(publicKey.getW())) 
                {
                    // при ошибке выбросить исключение
                    throw new IllegalArgumentException(); 
                }
            }
            if (certificateBase64 == null) certificate = null; 
            else {
                // получить закодированный сертификат
                byte[] encodedCertificate = Base64.getDecoder().decode(certificateBase64);

                // раскодировать сертификат
                certificate = new Certificate(encodedCertificate); 
                
                // проверить подпись сертификата
                if (certificateCA != null) PKI.verifyCertificate(
                    factory, null, certificate, certificateCA
                );
                // извлечь открытый ключ
                publicKey = (aladdin.capi.gost.gostr3410.ECPublicKey)
                    certificate.getPublicKey(factory); 

                // указать параметры ключа
                parameters = (aladdin.capi.gost.gostr3410.IECParameters)
                    publicKey.parameters(); 

                // проверить принадлежность точки кривой
                if (!parameters.getCurve().isPoint(publicKey.getW())) 
                {
                    // при ошибке выбросить исключение
                    throw new IllegalArgumentException(); 
                }
            }
            // указать личный ключ
            privateKey = new aladdin.capi.gost.gostr3410.ECPrivateKey(
                factory, null, publicKey.keyOID(), parameters, 
                Convert.toBigInteger(encodedPrivateKey, Endian.BIG_ENDIAN)
            ); 
            // извлечь значение личного ключа
            BigInteger x = ((aladdin.capi.gost.gostr3410.ECPrivateKey)privateKey).getS(); 
                
            // выполнить математические операции
            ECPoint check = parameters.getCurve().multiply(parameters.getGenerator(), x);
            
            // сравнить соответствие личного и открытого ключа
            if (!check.equals(publicKey.getW())) throw new IllegalArgumentException(); 
        }
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException   
        {
            // освободить выделенные ресурсы
            privateKey.close(); super.onClose(); 
        }
        // проверить подписанное сообщение
        public final byte[] testSignedMessage(String messageBase64) throws Exception
        {
            // получить закодированную структуру
            ContentInfo contentInfo = new ContentInfo(
                Encodable.decode(Base64.getDecoder().decode(messageBase64))
            );
            // извлечь внутренние данные
            SignedData signedData = new SignedData(contentInfo.inner()); 

            // проверить подпись данных
            aladdin.capi.CMS.verifySign(privateKey.factory(), 
                privateKey.scope(), otherCertificate, signedData
            ); 
            // вернуть подписанные данные
            return signedData.encapContentInfo().eContent().value(); 
        }
        public final byte[] testEnvelopedMessage(String messageBase64) throws Exception
        {
            // получить закодированную структуру
            ContentInfo contentInfo = new ContentInfo(
                Encodable.decode(Base64.getDecoder().decode(messageBase64))
            );
            // извлечь внутренние данные
            EnvelopedData envelopedData = new EnvelopedData(contentInfo.inner()); 

            // расшифровать данные
            return aladdin.capi.CMS.keyxDecryptData(privateKey, 
                certificate, otherCertificate, envelopedData).content; 
        }
        public static void test(Factory factory) throws Exception
        {
            String certificateCA = null; 
            try (CMS pki2001 = new CMS(factory, null, new byte[] {
                    (byte)0x0B, (byte)0x29, (byte)0x3B, (byte)0xE0, (byte)0x50, 
                    (byte)0xD0, (byte)0x08, (byte)0x2B, (byte)0xDA, (byte)0xE7, 
                    (byte)0x85, (byte)0x63, (byte)0x1A, (byte)0x6B, (byte)0xAB, 
                    (byte)0x68, (byte)0xF3, (byte)0x5B, (byte)0x42, (byte)0x78, 
                    (byte)0x6D, (byte)0x6D, (byte)0xDA, (byte)0x56, (byte)0xAF, 
                    (byte)0xAF, (byte)0x16, (byte)0x98, (byte)0x91, (byte)0x04, 
                    (byte)0x0F, (byte)0x77
                }, 
                "MIIB0DCCAX8CECv1xh7CEb0Xx9zUYma0LiEwCAYGKoUDAgIDMG0xHzAdBgNVBAMM" + 
                "Fkdvc3RSMzQxMC0yMDAxIGV4YW1wbGUxEjAQBgNVBAoMCUNyeXB0b1BybzELMAkG" + 
                "A1UEBhMCUlUxKTAnBgkqhkiG9w0BCQEWGkdvc3RSMzQxMC0yMDAxQGV4YW1wbGUu" + 
                "Y29tMB4XDTA1MDgxNjE0MTgyMFoXDTE1MDgxNjE0MTgyMFowbTEfMB0GA1UEAwwW" + 
                "R29zdFIzNDEwLTIwMDEgZXhhbXBsZTESMBAGA1UECgwJQ3J5cHRvUHJvMQswCQYD" + 
                "VQQGEwJSVTEpMCcGCSqGSIb3DQEJARYaR29zdFIzNDEwLTIwMDFAZXhhbXBsZS5j" + 
                "b20wYzAcBgYqhQMCAhMwEgYHKoUDAgIkAAYHKoUDAgIeAQNDAARAhJVodWACGkB1" + 
                "CM0TjDGJLP3lBQN6Q1z0bSsP508yfleP68wWuZWIA9CafIWuD+SN6qa7flbHy7Df" + 
                "D2a8yuoaYDAIBgYqhQMCAgMDQQA8L8kJRLcnqeyn1en7U23Sw6pkfEQu3u0xFkVP" + 
                "vFQ/3cHeF26NG+xxtZPz3TaTVXdoiYkXYiD02rEx1bUcM97i", certificateCA 
            )) {
                aladdin.capi.Test.println(new String(pki2001.testSignedMessage( 
                    "MIIBKAYJKoZIhvcNAQcCoIIBGTCCARUCAQExDDAKBgYqhQMCAgkFADAbBgkqhkiG" + 
                    "9w0BBwGgDgQMc2FtcGxlIHRleHQKMYHkMIHhAgEBMIGBMG0xHzAdBgNVBAMMFkdv" + 
                    "c3RSMzQxMC0yMDAxIGV4YW1wbGUxEjAQBgNVBAoMCUNyeXB0b1BybzELMAkGA1UE" + 
                    "BhMCUlUxKTAnBgkqhkiG9w0BCQEWGkdvc3RSMzQxMC0yMDAxQGV4YW1wbGUuY29t" + 
                    "AhAr9cYewhG9F8fc1GJmtC4hMAoGBiqFAwICCQUAMAoGBiqFAwICEwUABEDAw0LZ" + 
                    "P4/+JRERiHe/icPbg0IE1iD5aCqZ9v4wO+T0yPjVtNr74caRZzQfvKZ6DRJ7/RAl" + 
                    "xlHbjbL0jHF+7XKp"
                ), "windows-1251")); 
                aladdin.capi.Test.println(new String(pki2001.testEnvelopedMessage( 
                    "MIIBpAYJKoZIhvcNAQcDoIIBlTCCAZECAQIxggFQoYIBTAIBA6BloWMwHAYGKoUD" + 
                    "AgITMBIGByqFAwICJAAGByqFAwICHgEDQwAEQLNVOfRngZcrpcTZhB8n+4HtCDLm" + 
                    "mtTyAHi4/4Nk6tIdsHg8ff4DwfQG5DvMFrnF9vYZNxwXuKCqx9GhlLOlNiChCgQI" + 
                    "L/D20YZLMoowHgYGKoUDAgJgMBQGByqFAwICDQAwCQYHKoUDAgIfATCBszCBsDCB" + 
                    "gTBtMR8wHQYDVQQDDBZHb3N0UjM0MTAtMjAwMSBleGFtcGxlMRIwEAYDVQQKDAlD" + 
                    "cnlwdG9Qcm8xCzAJBgNVBAYTAlJVMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAt" + 
                    "MjAwMUBleGFtcGxlLmNvbQIQK/XGHsIRvRfH3NRiZrQuIQQqMCgEIBajHOfOTukN" + 
                    "8ex0aQRoHsefOu24Ox8dSn75pdnLGdXoBAST/YZ+MDgGCSqGSIb3DQEHATAdBgYq" + 
                    "hQMCAhUwEwQItzXhegc1oh0GByqFAwICHwGADDmxivS/qeJlJbZVyQ=="
                ), "windows-1251")); 
                aladdin.capi.Test.println(new String(pki2001.testEnvelopedMessage( 
                    "MIIBpwYJKoZIhvcNAQcDoIIBmDCCAZQCAQAxggFTMIIBTwIBADCBgTBtMR8wHQYD" + 
                    "VQQDDBZHb3N0UjM0MTAtMjAwMSBleGFtcGxlMRIwEAYDVQQKDAlDcnlwdG9Qcm8x" + 
                    "CzAJBgNVBAYTAlJVMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAwMUBleGFt" + 
                    "cGxlLmNvbQIQK/XGHsIRvRfH3NRiZrQuITAcBgYqhQMCAhMwEgYHKoUDAgIkAAYH" + 
                    "KoUDAgIeAQSBpzCBpDAoBCBqL6ghBpVon5/kR6qey2EVK35BYLxdjfv1PSgbGJr5" + 
                    "dQQENm2Yt6B4BgcqhQMCAh8BoGMwHAYGKoUDAgITMBIGByqFAwICJAAGByqFAwIC" + 
                    "HgEDQwAEQE0rLzOQ5tyj3VUqzd/g7/sx93N+Tv+/eImKK8PNMZQESw5gSJYf28dd" + 
                    "Em/askCKd7W96vLsNMsjn5uL3Z4SwPYECJeV4ywrrSsMMDgGCSqGSIb3DQEHATAd" + 
                    "BgYqhQMCAhUwEwQIvBCLHwv/NCkGByqFAwICHwGADKqOch3uT7Mu4w+hNw=="
                ), "windows-1251")); 
            }
            try (CMS pki2012_256 = new CMS(factory, null, 
                new byte[] {
                    (byte)0xBF, (byte)0xCF, (byte)0x1D, (byte)0x62, (byte)0x3E, 
                    (byte)0x5C, (byte)0xDD, (byte)0x30, (byte)0x32, (byte)0xA7, 
                    (byte)0xC6, (byte)0xEA, (byte)0xBB, (byte)0x4A, (byte)0x92, 
                    (byte)0x3C, (byte)0x46, (byte)0xE4, (byte)0x3D, (byte)0x64, 
                    (byte)0x0F, (byte)0xFE, (byte)0xAA, (byte)0xF2, (byte)0xC3, 
                    (byte)0xED, (byte)0x39, (byte)0xA8, (byte)0xFA, (byte)0x39, 
                    (byte)0x99, (byte)0x24            
                },                
                "MIICYjCCAg+gAwIBAgIBATAKBggqhQMHAQEDAjBWMSkwJwYJKoZIhvcNAQkBFhpH" + 
                "b3N0UjM0MTAtMjAxMkBleGFtcGxlLmNvbTEpMCcGA1UEAxMgR29zdFIzNDEwLTIw" + 
                "MTIgKDI1NiBiaXQpIGV4YW1wbGUwHhcNMTMxMTA1MTQwMjM3WhcNMzAxMTAxMTQw" + 
                "MjM3WjBWMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAxMkBleGFtcGxlLmNv" + 
                "bTEpMCcGA1UEAxMgR29zdFIzNDEwLTIwMTIgKDI1NiBiaXQpIGV4YW1wbGUwZjAf" + 
                "BggqhQMHAQEBATATBgcqhQMCAiQABggqhQMHAQECAgNDAARAut/Qw1MUq9KPqkdH" + 
                "C2xAF3K7TugHfo9n525D2s5mFZdD5pwf90/i4vF0mFmr9nfRwMYP4o0Pg1mOn5Rl" + 
                "aXNYraOBwDCBvTAdBgNVHQ4EFgQU1fIeN1HaPbw+XWUzbkJ+kHJUT0AwCwYDVR0P" + 
                "BAQDAgHGMA8GA1UdEwQIMAYBAf8CAQEwfgYDVR0BBHcwdYAU1fIeN1HaPbw+XWUz" + 
                "bkJ+kHJUT0ChWqRYMFYxKTAnBgkqhkiG9w0BCQEWGkdvc3RSMzQxMC0yMDEyQGV4" + 
                "YW1wbGUuY29tMSkwJwYDVQQDEyBHb3N0UjM0MTAtMjAxMiAoMjU2IGJpdCkgZXhh" + 
                "bXBsZYIBATAKBggqhQMHAQEDAgNBAF5bm4BbARR6hJLEoWJkOsYV3Hd7kXQQjz3C" + 
                "dqQfmHrz6TI6Xojdh/t8ckODv/587NS5/6KsM77vc6Wh90NAT2s=", certificateCA  
            )) {
                aladdin.capi.Test.println(new String(pki2012_256.testSignedMessage( 
                    "MIIBBQYJKoZIhvcNAQcCoIH3MIH0AgEBMQ4wDAYIKoUDBwEBAgIFADAbBgkqhkiG" + 
                    "9w0BBwGgDgQMVGVzdCBtZXNzYWdlMYHBMIG+AgEBMFswVjEpMCcGCSqGSIb3DQEJ" + 
                    "ARYaR29zdFIzNDEwLTIwMTJAZXhhbXBsZS5jb20xKTAnBgNVBAMTIEdvc3RSMzQx" + 
                    "MC0yMDEyICgyNTYgYml0KSBleGFtcGxlAgEBMAwGCCqFAwcBAQICBQAwDAYIKoUD" + 
                    "BwEBAQEFAARAkptb2ekZbC94FaGDQeP70ExvTkXtOY9zgz3cCco/hxPhXUVo3eCx" + 
                    "VNwDQ8enFItJZ8DEX4blZ8QtziNCMl5HbA==" 
                ), "windows-1251")); 
                aladdin.capi.Test.println(new String(pki2012_256.testEnvelopedMessage( 
                    "MIIBhgYJKoZIhvcNAQcDoIIBdzCCAXMCAQIxggEwoYIBLAIBA6BooWYwHwYIKoUD" + 
                    "BwEBAQEwEwYHKoUDAgIkAAYIKoUDBwEBAgIDQwAEQPAdWM4pO38iZ49UjaXQpq+a" + 
                    "jhTa4KwY4B9TFMK7AiYmbFKE0eX/wvu69kFMQ2o3OJTnMOlr1WHiPYOmNO6C5hOh" + 
//                  "CgQIX+vNomZakEIwIgYIKoUDBwEBAQEwFgYHKoUDAgINADALBgkqhQMHAQIFAQEw" + 
                    "CgQIX+vNomZakEIwIgYIKoUDBwEBBgEwFgYHKoUDAgINADALBgkqhQMHAQIFAQEw" + 
                    "gYwwgYkwWzBWMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAxMkBleGFtcGxl" + 
                    "LmNvbTEpMCcGA1UEAxMgR29zdFIzNDEwLTIwMTIgMjU2IGJpdHMgZXhjaGFuZ2UC" + 
                    "AQEEKjAoBCCNhrZOr7x2fsjjQAeDMv/tSoNRQSSQzzxgqdnYxJ3fIAQEgYLqVDA6" + 
                    "BgkqhkiG9w0BBwEwHwYGKoUDAgIVMBUECHVmR/S+hlYiBgkqhQMHAQIFAQGADEI9" + 
                    "UNjyuY+54uVcHw==" 
                ), "windows-1251")); 
                aladdin.capi.Test.println(new String(pki2012_256.testEnvelopedMessage( 
                    "MIIKGgYJKoZIhvcNAQcDoIIKCzCCCgcCAQAxggE0MIIBMAIBADBbMFYxKTAnBgkq" + 
                    "hkiG9w0BCQEWGkdvc3RSMzQxMC0yMDEyQGV4YW1wbGUuY29tMSkwJwYDVQQDEyBH" + 
                    "b3N0UjM0MTAtMjAxMiAyNTYgYml0cyBleGNoYW5nZQIBATAfBggqhQMHAQEBATAT" + 
                    "BgcqhQMCAiQABggqhQMHAQECAgSBrDCBqTAoBCCVJxUMdbKRzCJ5K1NWJIXnN7Ul" + 
                    "zaceeFlblA2qH4wZrgQEsHnIG6B9BgkqhQMHAQIFAQGgZjAfBggqhQMHAQEBATAT" + 
                    "BgcqhQMCAiQABggqhQMHAQECAgNDAARAFoqoLg1lV780co6GdwtjLtS4KCXv9VGR" + 
                    "sd7PTPHCT/5iGbvOlKNW2I8UhayJ0dv7RV7Nb1lDIxPxf4Mbp2CikgQI1b4+WpGE" + 
                    "sfQwggjIBgkqhkiG9w0BBwEwHwYGKoUDAgIVMBUECHYNkdvFoYdyBgkqhQMHAQIF" + 
                    "AQGAggiYvFFpJKILAFdXjcdLLYv4eruXzL/wOXL8y9HHIDMbSzV1GM033J5Yt/p4" + 
                    "H6JYe1L1hjAfE/BAAYBndof2sSUxC3/I7xj+b7M8BZ3GYPqATPtR4aCQDK6z91lx" + 
                    "nDBAWx0HdsStT5TOj/plMs4zJDadvIJLfjmGkt0Np8FSnSdDPOcJAO/jcwiOPopg" + 
                    "+Z8eIuZNmY4seegTLue+7DGqvqi1GdZdMnvXBFIKc9m5DUsC7LdyboqKImh6giZE" + 
                    "YZnxb8a2naersPylhrf+zp4Piwwv808yOrD6LliXUiH0RojlmuaQP4wBkb7m073h" + 
                    "MeAWEWSvyXzOvOOuFST/hxPEupiTRoHPUdfboJT3tNpizUhE384SrvXHpwpgivQ4" + 
                    "J0zF2/uzTBEupXR6dFC9rTHAK3X79SltqBNnHyIXBwe+BMqTmKTfnlPVHBUfTXZg" + 
                    "oakDItwKwa1MBOZeciwtUFza+7o9FZhKIandb848chGdgd5O9ksaXvPJDIPxQjZd" + 
                    "EBVhnXLlje4TScImwTdvYB8GsI8ljKb2bL3FjwQWGbPaOjXc2D9w+Ore8bk1E4TA" + 
                    "ayhypU7MH3Mq1EBZ4j0iROEFBQmYRZn8vAKZ0K7aPxcDeAnKAJxdokqrMkLgI6WX" + 
                    "0glh/3Cs9dI+0D2GqMSygauKCD0vTIo3atkEQswDZR4pMx88gB4gmx7iIGrc/ZXs" + 
                    "ZqHI7NQqeKtBwv2MCIj+/UTqdYDqbaniDwdVS8PE9nQnNU4gKffq3JbT+wRjJv6M" + 
                    "Dr231bQHgAsFTVKbZgoL4gj4V7bLQUmW06+W1BQUJ2+Sn7fp+Xet9Xd3cGtNdxzQ" + 
                    "zl6sGuiOlTNe0bfKP7QIMC7ekjflLBx8nwa2GZG19k3O0Z9JcDdN/kz6bGpPNssY" + 
                    "AIOkTvLQjxIM9MhRqIv6ee0rowTWQPwXJP7yHApop4XZvVX6h9gG2gazqbDej2lo" + 
                    "tAcfRAKj/LJ/bk9+OlNXOXVCKnwE1kXxZDsNJ51GdCungC56U/hmd3C1RhSLTpEc" + 
                    "FlOWgXKNjbn6SQrlq1yASKKr80T0fL7PFoYwKZoQbKMAVZQC1VBWQltHkEzdL73x" + 
                    "FwgZULNfdflF8sEhFC/zsVqckD/UnhzJz88PtCslMArJ7ntbEF1GzsSSfRfjBqnl" + 
                    "kSUreE5XX6+c9yp5HcJBiMzp6ZqqWWaED5Y5xp1hZeYjuKbDMfY4tbWVc7Hy0dD2" + 
                    "KGfZLp5umqvPNs7aVBPmvuxtrnxcJlUB8u2HoiHc6/TuhrpaopYGBhxL9+kezuLR" + 
                    "v18nsAg8HOmcCNUS46NXQj/Mdpx8W+RsyzCQkJjieT/Yed20Zxq1zJoXIS0xAaUH" + 
                    "TdE2dWqiT6TGlh/KQYk3KyFPNnDmzJm04a2VWIwpp4ypXyxrB7XxnVY6Q4YBYbZs" + 
                    "FycxGjJWqj7lwc+lgZ8YV2WJ4snEo2os8SsA2GFWcUMiVTHDnEJvphDHmhWsf26A" + 
                    "bbRqwaRXNjhj05DamTRsczgvfjdl1pk4lJYE4ES3nixtMe4s1X8nSmM4KvfyVDul" + 
                    "J8uTpw1ZFnolTdfEL63BSf4FREoEqKB7cKuD7cpn7Rg4kRdM0/BLZGuxkH+pGMsI" + 
                    "Bb8LecUWyjGsI6h74Wz/U2uBrfgdRqhR+UsfB2QLaRgM6kCXZ4vM0auuzBViFCwK" + 
                    "tYMHzZWWz8gyVtJ0mzt1DrHCMx4pTS4yOhv4RkXBS/rub4VhVIsOGOGar5ZYtH47" + 
                    "uBbdw3NC05JIFM7lI31d0s1fvvkTUR7eaqRW+SnR2c2oHpWlSO+Q0mrzx+vvOTdj" + 
                    "xa713YtklBvyUUQr2SIbsXGpFnwjn+sXK1onAavp/tEax8sNZvxg5yeseFcWn+gD" + 
                    "4rjk9FiSd1wp4fTDQFJ19evqruqKlq6k18l/ZAyUcEbIWSz2s3HfAAoAQyFPX1Q2" + 
                    "95gVhRRw6lP4S6VPCfn/f+5jV4TcT6W/giRaHIk9Hty+g8bx1bFXaKVkQZ5R2Vmk" + 
                    "qsZ65ZgCrYQJmcErPmYybvP7NBeDS4AOSgBQAGMQF4xywdNm6bniWWo3N/xkFv32" + 
                    "/25x8okGgD8QcYKmhzieLSSzOvM/exB14RO84YZOkZzm01Jll0nac/LEazKoVWbn" + 
                    "0VdcQ7pYEOqeMBXipsicNVYA/uhonp6op9cpIVYafPr0npCGwwhwcRuOrgSaZyCn" + 
                    "VG2tPkEOv9LKmUbhnaDA2YUSzOOjcCpIVvTSBnUEiorYpfRYgQLrbcd2qhVvNCLX" + 
                    "8ujZfMqXQXK8n5BK8JxNtczvaf+/2dfv1dQl0lHEAQhbNcsJ0t5GPhsSCC5oMBJl" + 
                    "ZJuOEO/8PBWKEnMZOM+Dz7gEgsBhGyMFFrKpiwQRpyEshSD2QpnK6Lp0t5C8Za2G" + 
                    "lhyZsEr+93AYOb5mm5+z02B4Yq9+RpepvjoqVeq/2uywZNq9MS98zVgNsmpryvTZ" + 
                    "3HJHHB20u2jcVu0G3Nhiv22lD70JWCYFAOupjgVcUcaBxjxwUMAvgHg7JZqs6mC6" + 
                    "tvTKwQ4NtDhoAhARlDeWSwCWb2vPH2H7Lmqokif1RfvJ0hrLzkJuHdWrzIYzXpPs" + 
                    "+v9XJxLvbdKi9KU1Halq9S8dXT1fvs9DJTpUV/KW7QkRsTQJhTJBkQ07WUSJ4gBS" + 
                    "Qp4efxSRNIfMj7DR6qLLf13RpIPTJO9/+gNuBIFcupWVfUL7tJZt8Qsf9eGwZfP+" + 
                    "YyhjC8AyZjH4/9RzLHSjuq6apgw3Mzw0j572Xg6xDLMK8C3Tn/vrLOvAd96b9MkF" + 
                    "3+ZHSLW3IgOiy+1jvK/20CZxNWc+pey8v4zji1hI17iohsipX/uZKRxhxF6+Xn2R" + 
                    "UQp6qoxHAspNXgWQ57xg7C3+gmi4ciVr0fT9pg54ogcowrRH+I6wd0EpeWPbzfnQ" + 
                    "pRmMVN+YtRsrEHwH3ToQ/i4vrtgA+eONuKT2uKZFikxA+VNmeeGdhkgqETMihQ=="
                ), "windows-1251")); 
            }
            try (CMS pki2012_512 = new CMS(factory, null, 
                new byte[] {
                    (byte)0x3F, (byte)0xC0, (byte)0x1C, (byte)0xDC, 
                    (byte)0xD4, (byte)0xEC, (byte)0x5F, (byte)0x97, 
                    (byte)0x2E, (byte)0xB4, (byte)0x82, (byte)0x77, 
                    (byte)0x4C, (byte)0x41, (byte)0xE6, (byte)0x6D, 
                    (byte)0xB7, (byte)0xF3, (byte)0x80, (byte)0x52, 
                    (byte)0x8D, (byte)0xFE, (byte)0x9E, (byte)0x67, 
                    (byte)0x99, (byte)0x2B, (byte)0xA0, (byte)0x5A, 
                    (byte)0xEE, (byte)0x46, (byte)0x24, (byte)0x35, 
                    (byte)0x75, (byte)0x75, (byte)0x30, (byte)0xE6, 
                    (byte)0x41, (byte)0x07, (byte)0x7C, (byte)0xE5, 
                    (byte)0x87, (byte)0xB9, (byte)0x76, (byte)0xC8, 
                    (byte)0xEE, (byte)0xB4, (byte)0x8C, (byte)0x48, 
                    (byte)0xFD, (byte)0x33, (byte)0xFD, (byte)0x17, 
                    (byte)0x5F, (byte)0x0C, (byte)0x7D, (byte)0xE6, 
                    (byte)0xA4, (byte)0x4E, (byte)0x01, (byte)0x4E, 
                    (byte)0x6B, (byte)0xCB, (byte)0x07, (byte)0x4B
                },                 
                "MIIC6DCCAlSgAwIBAgIBATAKBggqhQMHAQEDAzBWMSkwJwYJKoZIhvcNAQkBFhpH" + 
                "b3N0UjM0MTAtMjAxMkBleGFtcGxlLmNvbTEpMCcGA1UEAxMgR29zdFIzNDEwLTIw" + 
                "MTIgKDUxMiBiaXQpIGV4YW1wbGUwHhcNMTMxMDA0MDczNjA0WhcNMzAxMDAxMDcz" + 
                "NjA0WjBWMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAxMkBleGFtcGxlLmNv" + 
                "bTEpMCcGA1UEAxMgR29zdFIzNDEwLTIwMTIgKDUxMiBiaXQpIGV4YW1wbGUwgaow" + 
                "IQYIKoUDBwEBAQIwFQYJKoUDBwECAQICBggqhQMHAQECAwOBhAAEgYATGQ9VCiM5" + 
                "FRGCQ8MEz2F1dANqhaEuywa8CbxOnTvaGJpFQVXQwkwvLFAKh7hk542vOEtxpKtT" + 
                "CXfGf84nRhMH/Q9bZeAc2eO/yhxrsQhTBufa1Fuou2oe/jUOaG6RAtUUvRzhNTpp" + 
                "RGGl1+EIY2vzzUua9j9Ol/gAoy/LNKQIfqOBwDCBvTAdBgNVHQ4EFgQUPcbTRXJZ" + 
                "nHtjj+eBP7b5lcTMekIwCwYDVR0PBAQDAgHGMA8GA1UdEwQIMAYBAf8CAQEwfgYD" + 
                "VR0BBHcwdYAUPcbTRXJZnHtjj+eBP7b5lcTMekKhWqRYMFYxKTAnBgkqhkiG9w0B" + 
                "CQEWGkdvc3RSMzQxMC0yMDEyQGV4YW1wbGUuY29tMSkwJwYDVQQDEyBHb3N0UjM0" + 
                "MTAtMjAxMiAoNTEyIGJpdCkgZXhhbXBsZYIBATAKBggqhQMHAQEDAwOBgQBObS7o" + 
                "ppPTXzHyVR1DtPa8b57nudJzI4czhsfeX5HDntOq45t9B/qSs8dC6eGxbhHZ9zCO" + 
                "SFtxWYdmg0au8XI9Xb8vTC1qdwWID7FFjMWDNQZb6lYh/J+8F2xKylvB5nIlRZqO" + 
                "o3eUNFkNyHJwQCk2WoOlO16zwGk2tdKH4KmD5w==", certificateCA
            )) {
                aladdin.capi.Test.println(new String(pki2012_512.testSignedMessage( 
                    "MIIBSQYJKoZIhvcNAQcCoIIBOjCCATYCAQExDjAMBggqhQMHAQECAwUAMBsGCSqG" + 
                    "SIb3DQEHAaAOBAxUZXN0IG1lc3NhZ2UxggECMIH/AgEBMFswVjEpMCcGCSqGSIb3" + 
                    "DQEJARYaR29zdFIzNDEwLTIwMTJAZXhhbXBsZS5jb20xKTAnBgNVBAMTIEdvc3RS" + 
                    "MzQxMC0yMDEyICg1MTIgYml0KSBleGFtcGxlAgEBMAwGCCqFAwcBAQIDBQAwDAYI" + 
                    "KoUDBwEBAQIFAASBgFyVohNhMHUi/+RAF3Gh/cC7why6v+4jPWVlx1TYlXtV8Hje" + 
                    "hI2Y+rP52/LO6EUHG/XcwCBbUxmRWsbUSRRBAexmaafkSdvv2FFwC8kHOcti+UPX" + 
                    "PS+KRYxT8vhcsBLWWxDkc1McI7aF09hqtED36mQOfACzeJjEoUjALpmJob1V" 
                ), "windows-1251")); 
                aladdin.capi.Test.println(new String(pki2012_512.testEnvelopedMessage( 
                    "MIIBzAYJKoZIhvcNAQcDoIIBvTCCAbkCAQIxggF2oYIBcgIBA6CBraGBqjAhBggq" + 
                    "hQMHAQEBAjAVBgkqhQMHAQIBAgIGCCqFAwcBAQIDA4GEAASBgCB0nQy/Ljva/mRj" + 
                    "w6o+eDKIvnxwYIQB5XCHhZhCpHNZiWcFxFpYXZLWRPKifOxV7NStvqGE1+fkfhBe" + 
                    "btkQu0tdC1XL3LO2Cp/jX16XhW/IP5rKV84qWr1Owy/6tnSsNRb+ez6IttwVvaVV" + 
//                  "pA6ONFy9p9gawoC8nitvAVJkWW0PoQoECDVfxzxgMTAHMCIGCCqFAwcBAQECMBYG" + 
                    "pA6ONFy9p9gawoC8nitvAVJkWW0PoQoECDVfxzxgMTAHMCIGCCqFAwcBAQYCMBYG" +
                    "ByqFAwICDQAwCwYJKoUDBwECBQEBMIGMMIGJMFswVjEpMCcGCSqGSIb3DQEJARYa" + 
                    "R29zdFIzNDEwLTIwMTJAZXhhbXBsZS5jb20xKTAnBgNVBAMTIEdvc3RSMzQxMC0y" + 
                    "MDEyIDUxMiBiaXRzIGV4Y2hhbmdlAgEBBCowKAQg8C/OcxRR0Uq8nDjHrQlayFb3" + 
                    "WFUZEnEuAKcuG6dTOawEBLhi9hIwOgYJKoZIhvcNAQcBMB8GBiqFAwICFTAVBAiD" + 
                    "1wH+CX6CwgYJKoUDBwECBQEBgAzUvQI4H2zRfgNgdlY="
                ), "windows-1251")); 
                aladdin.capi.Test.println(new String(pki2012_512.testEnvelopedMessage( 
                    "MIIB0gYJKoZIhvcNAQcDoIIBwzCCAb8CAQAxggF8MIIBeAIBADBbMFYxKTAnBgkq" + 
                    "hkiG9w0BCQEWGkdvc3RSMzQxMC0yMDEyQGV4YW1wbGUuY29tMSkwJwYDVQQDEyBH" + 
                    "b3N0UjM0MTAtMjAxMiA1MTIgYml0cyBleGNoYW5nZQIBATAhBggqhQMHAQEBAjAV" + 
                    "BgkqhQMHAQIBAgIGCCqFAwcBAQIDBIHyMIHvMCgEIIsYzbVLn33aLinQ7SLNA7y+" + 
                    "Lrm02khqDCfXrNS9iiMhBATerS8zoIHCBgkqhQMHAQIFAQGggaowIQYIKoUDBwEB" + 
                    "AQIwFQYJKoUDBwECAQICBggqhQMHAQECAwOBhAAEgYAYiTVLKpSGaAvjJEDQ0hdK" + 
                    "qR/jek5Q9Q2pXC+NkOimQh7dpCi+wcaHlPcBk96hmpnOFvLaiokX8V6jqtBl5gdk" + 
                    "M40kOXv8kcDdTzEVKA/ZLxA8xanL+gTD6ZjaPsUu06nsA2MoMBWcHLUzueaP3bGT" + 
                    "/yHTV+Za5xdcQehag/lNBgQIvCw4uUl0XC4wOgYJKoZIhvcNAQcBMB8GBiqFAwIC" + 
                    "FTAVBAj+1QzaXaN9FwYJKoUDBwECBQEBgAyK54euw0sHhEVEkA0="
                ), "windows-1251")); 
            }
            certificateCA = 
                "MIIB8DCCAZ2gAwIBAgIEAYy6gTAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2" + 
                "MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEw" + 
                "MTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA4MQ0wCwYDVQQKEwRUSzI2MScwJQYD" + 
                "VQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwaDAhBggqhQMHAQEB" + 
                "ATAVBgkqhQMHAQIBAQEGCCqFAwcBAQICA0MABEAaSoKcjw54UACci6svELNF0IYM" + 
                "RIW8urUsqamIpoG46XCqrVOuI6Q13N4dwcRsbZdqByf+GC2f5ZfO3baN5bTKo4GF" + 
                "MIGCMGEGA1UdAQRaMFiAFIDZDPeZ+GZNk1OJjsCecS2npzESoTowODENMAsGA1UE" + 
                "ChMEVEsyNjEnMCUGA1UEAxMeQ0EgVEsyNjogR09TVCAzNC4xMC0xMiAyNTYtYml0" + 
                "ggQBjLqBMB0GA1UdDgQWBBSA2Qz3mfhmTZNTiY7AnnEtp6cxEjAKBggqhQMHAQED" + 
                "AgNBAAgv248F4OeNCkhlzJWec0evHYnMBlSzk1lDm0F875B7CqMrKh2MtJHXenbj" + 
                "Gc2uRn2IwgmSf/LZDrYsKKqZSxk="; 
            try (CMS pki2012_256 = new CMS(factory, 
                "MIIB8jCCAZ+gAwIBAgIEAYy6gzAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2" + 
                "MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEw" + 
                "MTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA6MQ0wCwYDVQQKEwRUSzI2MSkwJwYD" + 
                "VQQDEyBSRUNJUElFTlQ6IEdPU1QgMzQuMTAtMTIgMjU2LWJpdDBoMCEGCCqFAwcB" + 
                "AQEBMBUGCSqFAwcBAgEBAQYIKoUDBwEBAgIDQwAEQL8nghlzLGMKWHuWhNMPMN5u" + 
                "L6SkGqRiJ6qZxZb+4dPKbBT9LNVvNKtwUed+BeE5kfqOfolPgFusnL1rnO9yREOj" + 
                "gYUwgYIwYQYDVR0BBFowWIAUgNkM95n4Zk2TU4mOwJ5xLaenMRKhOjA4MQ0wCwYD" + 
                "VQQKEwRUSzI2MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1i" + 
                "aXSCBAGMuoEwHQYDVR0OBBYEFLue+PUb9Oe+pziBU+MvNejjgrzFMAoGCCqFAwcB" + 
                "AQMCA0EAPP9Oad1/5jwokSjPpccsQ0xCdVYM+mGQ0IbpiZxQj8gnkt8sq4jR6Ya+" + 
                "I/BDkbZNDNE27TU1p3t5rE9NMEeViA==",
                new byte[] {
                    (byte)0x0D, (byte)0xC8, (byte)0xDC, (byte)0x1F, 
                    (byte)0xF2, (byte)0xBC, (byte)0x11, (byte)0x4B, 
                    (byte)0xAB, (byte)0xC3, (byte)0xF1, (byte)0xCA, 
                    (byte)0x8C, (byte)0x51, (byte)0xE4, (byte)0xF5, 
                    (byte)0x86, (byte)0x10, (byte)0x42, (byte)0x7E, 
                    (byte)0x19, (byte)0x7B, (byte)0x1C, (byte)0x2F, 
                    (byte)0xBD, (byte)0xBA, (byte)0x4A, (byte)0xE5, 
                    (byte)0x8C, (byte)0xBF, (byte)0xB7, (byte)0xCE
                }, 
                "MIIB8zCCAaCgAwIBAgIEAYy6gjAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2" + 
                "MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEw" + 
                "MTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA7MQ0wCwYDVQQKEwRUSzI2MSowKAYD" + 
                "VQQDEyFPUklHSU5BVE9SOiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwaDAhBggqhQMH" + 
                "AQEBATAVBgkqhQMHAQIBAQEGCCqFAwcBAQICA0MABECWKQ0TYllqg4GmY3tBJiyz" + 
                "pXUN+aOV9WbmTUinqrmEHP7KCNzoAzFg+04SSQpNNSHpQnm+jLAZhuJaJfqZ6VbT" + 
                "o4GFMIGCMGEGA1UdAQRaMFiAFIDZDPeZ+GZNk1OJjsCecS2npzESoTowODENMAsG" + 
                "A1UEChMEVEsyNjEnMCUGA1UEAxMeQ0EgVEsyNjogR09TVCAzNC4xMC0xMiAyNTYt" + 
                "Yml0ggQBjLqBMB0GA1UdDgQWBBTRnChHSWbQYwnJC62n2zu5Njd03zAKBggqhQMH" + 
                "AQEDAgNBAB41oijaXSEn58l78y2rhxY35/lKEq4XWZ70FtsNlVxWATyzgO5Wliwn" + 
                "t1O4GoZsxx8r6T/i7VG65UNmQlwdOKQ=", certificateCA
            )) {
                aladdin.capi.Test.println(new String(pki2012_256.testSignedMessage( 
                    "MIIDAQYJKoZIhvcNAQcCoIIC8jCCAu4CAQExDDAKBggqhQMHAQECAjA7BgkqhkiG" + 
                    "9w0BBwGgLgQsyu7t8vDu6/zt++kg7/Do7OXwIOTr/yDx8vDz6vLz8PsgU2lnbmVk" + 
                    "RGF0YS6gggH3MIIB8zCCAaCgAwIBAgIEAYy6gjAKBggqhQMHAQEDAjA4MQ0wCwYD" + 
                    "VQQKEwRUSzI2MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1i" + 
                    "aXQwHhcNMDEwMTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA7MQ0wCwYDVQQKEwRU" + 
                    "SzI2MSowKAYDVQQDEyFPUklHSU5BVE9SOiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQw" + 
                    "aDAhBggqhQMHAQEBATAVBgkqhQMHAQIBAQEGCCqFAweBAQICA0MABECWKQ0TYllq" + 
                    "g4GmY3tBJiyzpXUN+aOV9WbmTUinqrmEHP7KCNzoAzFg+04SSQpNNSHpQnm+jLAZ" + 
                    "huJaJfqZ6VbTo4GFMIGCMGEGA1UdAQRaMFiAFIDZDPeZ+GZNk1OJjsCecS2npzES" + 
                    "oTowODENMAsGA1UEChMEVEsyNjEnMCUGA1UEAxMeQ0EgVEsyNjogR09TVCAzNC4x" + 
                    "MC0xMiAyNTYtYml0ggQBjLqBMB0GA1UdDgQWBBTRnChHSWbQYwnJC62n2zu5Njd0" + 
                    "3zAKBggqhQMHAQEDAgNBAB41oijaXSEn58l78y2rhxY35/lKEq4XWZ70FtsNlVxW" + 
                    "ATyzgO5Wliwnt1O4GoZsxx8r6T/i7VG65UNmQlwdOKQxgaIwgZ8CAQEwQDA4MQ0w" + 
                    "CwYDVQQKEwRUSzI2MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1" + 
                    "Ni1iaXQCBAGMuoIwCgYIKoUDBwEBAgIwCgYIKoUDBwEBAQEEQC6jZPA59szL9FiA" + 
                    "0wC71EBE42ap6gKxklT800cu2FvbLu972GJYNSI7+UeanVU37OVWyenEXi2E5HkU" + 
                    "94kBe8Q="                    
                ), "windows-1251")); 
                aladdin.capi.Test.println(new String(pki2012_256.testEnvelopedMessage( 
                    "MIIBawYJKoZIhvcNAQcDoIIBXDCCAVgCAQIxgfehgfQCAQOgQjBAMDgxDTALBgNV" + 
                    "BAoTBFRLMjYxJzAlBgNVBAMTHkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJp" + 
                    "dAIEAYy6gqEiBCBvcfyuSF57y8vVyaw8Z0ch3wjC4lPKTrpVRXty4Rhk5DAXBgkq" + 
                    "hQMHAQEHAQEwCgYIKoUDBwEBBgEwbjBsMEAwODENMAsGA1UEChMEVEsyNjEnMCUG" + 
                    "A1UEAxMeQ0EgVEsyNjogR09TVCAzNC4xMC0xMiAyNTYtYml0AgQBjLqDBChPbi6B" + 
                    "krXuLPexPAL2oUGCFWDGQHqINL5ExuMBG7/5XQRqriKARVa0MFkGCSqGSIb3DQEH" + 
                    "ATAbBgkqhQMHAQEFAQEwDgQMdNdCKnYAAAAwqTEDgC9O2bYyTGQJ8WUQGq0zHwzX" + 
                    "L0jFhWHTF1tcAxYmd9pX5i89UwIxhtYqyjX1QHju2g=="
                ), "windows-1251")); 
                aladdin.capi.Test.println(new String(pki2012_256.testEnvelopedMessage( 
                    "MIIBlQYJKoZIhvcNAQcDoIIBhjCCAYICAQAxggEcMIIBGAIBADBAMDgxDTALBgNV" + 
                    "BAoTBFRLMjYxJzAlBgNVBAMTHkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJp" + 
                    "dAIEAYy6gzAXBgkqhQMHAQEHAgEwCgYIKoUDBwEBBgEEgbcwgbQEMFiMredFR3Mv" + 
                    "3g2wqyVXRnrhYEBMNFaqqgBpHwPQh3bF98tt9HZPxRDCww0OPfxeuTBeMBcGCCqF" + 
                    "AwcBAQEBMAsGCSqFAwcBAgEBAQNDAARAdFJ9ww+3ptvQiaQpizCldNYhl4DB1rl8" + 
                    "Fx/2FIgnwssCbYRQ+UuRsTk9dfLLTGJG3JIEXKFxXWBgOrK965A5pAQg9f2/EHxG" + 
                    "DfetwCe1a6uUDCWD+wp5dYOpfkry8YRDEJgwXQYJKoZIhvcNAQcBMB8GCSqFAwcB" + 
                    "AQUCATASBBDUHNxmVclO/v3OaY9P7jxOgC+sD9CHGlEMRUpfGn6yfFDMExmYeby8" + 
                    "LzdPJe1MkYV0qQgdC1zI3nQ7/4taf+4zRA=="
                ), "windows-1251")); 
            }
            try (CMS pki2012_512 = new CMS(factory, 
                "MIICNTCCAeKgAwIBAgIEAYy6hTAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2"  +
                "MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEw"  +
                "MTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA6MQ0wCwYDVQQKEwRUSzI2MSkwJwYD"  +
                "VQQDEyBSRUNJUElFTlQ6IEdPU1QgMzQuMTAtMTIgNTEyLWJpdDCBqjAhBggqhQMH"  +
                "AQEBAjAVBgkqhQMHAQIBAgEGCCqFAwcBAQIDA4GEAASBgKauwGYvUkzz19g0LP/p"  +
                "zeRdmwy1m+QSy9W5ZrL/AGuJofm2ARjz40ozNbW6bp9hkHu8x66LX7u5zz+QeS2+"  +
                "X5om18UXriComgO0+qhZbc+Hzu0eQ8FjOd8LpLk3TzzfBltfLOX5IiPLjeum+pSP"  +
                "0QjoXAVcrop//B4yvZIukvROo4GFMIGCMGEGA1UdAQRaMFiAFIDZDPeZ+GZNk1OJ"  +
                "jsCecS2npzESoTowODENMAsGA1UEChMEVEsyNjEnMCUGA1UEAxMeQ0EgVEsyNjog"  +
                "R09TVCAzNC4xMC0xMiAyNTYtYml0ggQBjLqBMB0GA1UdDgQWBBSrXT5VKhm/5uff"  +
                "kwW0XpG19k6AajAKBggqhQMHAQEDAgNBAAJBpsHRrQKZGb22LOzaReEB8rl2MbIR"  +
                "ja64NaM5h+cAFoHm6t/k+ziLh2A11rTakR+5of4NQ3EjEhuPtomP2tc=",                 
                new byte[] {
                    (byte)0xA5, (byte)0x03, (byte)0x15, (byte)0x98, 
                    (byte)0x1F, (byte)0x0A, (byte)0x7C, (byte)0x7F, 
                    (byte)0xC0, (byte)0x5B, (byte)0x4E, (byte)0xB9, 
                    (byte)0x59, (byte)0x1A, (byte)0x62, (byte)0xB1, 
                    (byte)0xF8, (byte)0x4B, (byte)0xD6, (byte)0xFD, 
                    (byte)0x51, (byte)0x8A, (byte)0xCF, (byte)0xCE, 
                    (byte)0xDF, (byte)0x0A, (byte)0x7C, (byte)0x9C, 
                    (byte)0xF3, (byte)0x88, (byte)0xD1, (byte)0xF1, 
                    (byte)0x87, (byte)0x57, (byte)0xC0, (byte)0x56, 
                    (byte)0xAD, (byte)0xA5, (byte)0xB3, (byte)0x8C, 
                    (byte)0xBF, (byte)0x24, (byte)0xCD, (byte)0xDB, 
                    (byte)0x0F, (byte)0x15, (byte)0x19, (byte)0xEF, 
                    (byte)0x72, (byte)0xDB, (byte)0x17, (byte)0x12, 
                    (byte)0xCE, (byte)0xF1, (byte)0x92, (byte)0x09, 
                    (byte)0x52, (byte)0xE9, (byte)0x4A, (byte)0xF1, 
                    (byte)0xF9, (byte)0xC5, (byte)0x75, (byte)0xDC                    
                }, 
                "MIICNjCCAeOgAwIBAgIEAYy6hDAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2" + 
                "MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEw" + 
                "MTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA7MQ0wCwYDVQQKEwRUSzI2MSowKAYD" + 
                "VQQDEyFPUklHSU5BVE9SOiBHT1NUIDM0LjEwLTEyIDUxMi1iaXQwgaowIQYIKoUD" + 
                "BwEBAQIwFQYJKoUDBwECAQIBBggqhQMHAQECAwOBhAAEgYC0i7davCkOGGVcYqFP" + 
                "tS1fUIROzB0fYARIe0tclTRpare/qzRuVRapqzzO+K21LDpYVfDPs2Sqa13ZN+Ts" + 
                "/JUlv59qCFB2cYpFyB/0kh4+K79yvz7r8+4WE0EmZf8T3ae/J1Jo6xGunecH1/G4" + 
                "hMts9HYLnxbwJDMNVGuIHV6gzqOBhTCBgjBhBgNVHQEEWjBYgBSA2Qz3mfhmTZNT" + 
                "iY7AnnEtp6cxEqE6MDgxDTALBgNVBAoTBFRLMjYxJzAlBgNVBAMTHkNBIFRLMjY6" + 
                "IEdPU1QgMzQuMTAtMTIgMjU2LWJpdIIEAYy6gTAdBgNVHQ4EFgQUK+l9HAscONGx" + 
                "zCcRpxRAmFHvlXowCgYIKoUDBwEBAwIDQQAbjA0Q41/rIKOOvjHKsAsoEJM+WJf6" + 
                "/PKXg2JaStthmw99bdtwwkU/qDbcje2tF6mt+XWyQBXwvfeES1GFY9fJ", certificateCA               
            )) {
                aladdin.capi.Test.println(new String(pki2012_512.testSignedMessage( 
                    "MIIENwYJKoZIhvcNAQcCoIIEKDCCBCQCAQExDDAKBggqhQMHAQECAzA7BgkqhkiG" + 
                    "9w0BBwGgLgQsyu7t8vDu6/zt++kg7/Do7OXwIOTr/yDx8vDz6vLz8PsgU2lnbmVk" + 
                    "RGF0YS6gggI6MIICNjCCAeOgAwIBAgIEAYy6hDAKBggqhQMHAQEDAjA4MQ0wCwYD" + 
                    "VQQKEwRUSzI2MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1i" + 
                    "aXQwHhcNMDEwMTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA7MQ0wCwYDVQQKEwRU" + 
                    "SzI2MSowKAYDVQQDEyFPUklHSU5BVE9SOiBHT1NUIDM0LjEwLTEyIDUxMi1iaXQw" + 
                    "gaowIQYIKoUDBwEBAQIwFQYJKoUDBwECAQIBBggqhQMHAQECAwOBhAAEgYC0i7da" + 
                    "vCkOGGVcYqFPtS1fUIROzB0fYARIe0tclTRpare/qzRuVRapqzZO+K21LDpYVfDP" + 
                    "s2Sqa13ZN+Ts/JUlv59qCFB2cYpFyB/0kh4+K79yvz7r8+4WE0EmZf8T3ae/J1Jo" + 
                    "6xGunecH1/G4hMts9HYLnxbwJDMNVGuIHV6gzqOBhTCBgjBhBgNVHQEEWjBYgBSA" + 
                    "2Qz3mfhmTZNTiY7AnnEtp6cxEqE6MDgxDTALBgNVBAoTBFRLMjYxJzAlBgNVBAMT" + 
                    "HkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJpdIIEAYy6gTAdBgNVHQ4EFgQU" + 
                    "K+l9HAscONGxzCcRpxRAmFHvlXowCgYIKoUDBwEBAwIDQQAbjA0Q41/rIKOOvjHK" + 
                    "sAsoEJM+WJf6/PKXg2JaStthmw99bdtwwkU/qDbcje2tF6mt+XWyQBXwvfeES1GF" + 
                    "Y9fJMYIBlDCCAZACAQEwQDA4MQ0wCwYDVQQKEwRUSzI2MScwJQYDVQQDEx5DQSBU" + 
                    "SzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQCBAGMuoQwCgYIKoUDBwEBAgOgga0w" + 
                    "GAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTkwMzIw" + 
                    "MTk1NTIyWjAiBgkqhkiG9w0BCWIxFQQTU2lnbmVkIGF0dHIncyB2YWx1ZTBPBgkq" + 
                    "hkiG9w0BCQQxQgRAUdPHEukF5BIfo9DoQIMdnB0ZLkzq0RueEUZSNv07A7C+GKWi" + 
                    "G62fueArg8uPCHPTUN6d/42p33fgMkEwH7f7cDAKBggqhQMHAQEBAgSBgGUnVka8" + 
                    "FvTlClmOtj/FUUacBdE/nEBeMLOO/535VDYrXlftPE6zQf/4ghS7TQG2VRGQ3GWD" + 
                    "+L3+W09A7d5uyyTEbvgtdllUG0OyqFwKmJEaYsMin87SFVs0cn1PGV1fOKeLluZa" + 
                    "bLx5whxd+mzlpekL5i6ImRX+TpERxrA/xSe5"                
                ), "windows-1251")); 
                aladdin.capi.Test.println(new String(pki2012_512.testEnvelopedMessage( 
                    "MIIB/gYJKoZIhvcNAQcDoIIB7zCCAesCAQIxggFioYIBXgIBA6CBo6GBoDAXBggq" + 
                    "hQMHAQEBAjALBgkqhQMHAQIBAgEDgYQABIGAe+itJVNbHM35RHfzuwFJPYdPXqtW" + 
                    "8hNEF7Z/XFEE2T71SRkhFX7ozYKQNh/TkVY9D4vG0LnD9Znr/pJyOjpsNb+dPcKX" + 
                    "Kbk/0JQxoPGHxFzASVAFq0ov/yBe2XGFWMeKUqtaAr7SvoYS0oEhT5EuT8BXmecd" + 
                    "nRe7NqOzESpb15ahIgQgsqHxOcdOp03l11S7k3OH1k1HNa5F8m9ctrOzH2846FMw" + 
                    "FwYJKoUDBwEBBwIBMAoGCCqFAwcBAQYCMHYwdDBAMDgxDTALBgNVBAoTBFRLMjYx" + 
                    "JzAlBgNVBAMTHkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJpdAIEAYy6hQQw" + 
                    "SxLc18zMwzLwXbcKqYhV/VzsdBgVArOHsSBIbaThJWE7zI37VGPMQJM5VXJ7GVcL" + 
                    "MF0GCSqGSIb3DQEHATAfBgkqhQMHAQEFAgIwEgQQ6EeVlADDCz2cdEWKy+tM94Av" + 
                    "yIFl/Ie4VeFFuczTsMsIaOUEe3Jn9GeVp8hZSj3O2q4hslQ/u/+Gj4QkSHm/M0ih" + 
                    "ITAfBgkqhQMHAQAGAQExEgQQs1t6D3J3WCEvxunnEE15NQ=="
                ), "windows-1251")); 
                aladdin.capi.Test.println(new String(pki2012_512.testEnvelopedMessage( 
                    "MIIB5wYJKoZIhvcNAQcDoIIB2DCCAdQCAQAxggFXMIIBUwIBADBAMDgxDTALBgNV" + 
                    "BAoTBFRLMjYxJzAlBgNVBAMTHkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJp" + 
                    "dAIEAYy6hTAXBgkqhQMHAQEHAQEwCgYIKoUDBwEBBgIEgfIwge8EKLgwbJFP21Qe" + 
                    "yKTSzdBqEqvb59bsbZ+xF5+s2Zo0vKNZTYuoIkG7Ks4wgaAwFwYIKoUDBwEBAQIw" + 
                    "CwYJKoUDBwECAQIBA4GEAASBgNPm7e14dXH70hCJhp3PJjBgj45ptP8DB5Cvt2jD" + 
                    "PCnFCOQUugmkMXcDEGoaYiPMicjSJvhZhyOQuwiTveEzRFQE2qLbK51nUJOa0BC9" + 
                    "/4G1v5t79ihoLr1xB5fc4cduy29YE/tb0CU9o14ZyVJdmqzLaSwjDtqLBh+jqD54" + 
                    "KpVJBCBOzTnW69sZQBrqTqxzQI3j4QCpUA1my8IYxUtxlni3pjBZBgkqhkiG9w0B" + 
                    "BwEwGwYJKoUDBwEBBQECMA4EDNmoGe4ZUZlF98u8x4AvoyuvFwsqPRN5DQn+obUB" + 
                    "gfrwMYfqmeZ34MAkb3QYcFyck7+kptHr8wxlO/6/mNGhGTAXBgkqhQMHAQAGAQEx" + 
                    "CgQIyyOpgBfMHxM="
                ), "windows-1251")); 
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // ГОСТ PKCS12
    ////////////////////////////////////////////////////////////////////////////
    public static abstract class PKCS12
    {
        private static Certificate getCertificate(
            String certificateBase64) throws Exception
        {
            // получить закодированный сертификат
            byte[] encodedCertificate = Base64.getDecoder().decode(certificateBase64);

            // раскодировать сертификат
            return new Certificate(encodedCertificate); 
        }
        private static IPrivateKey getPrivateKey(
            Factory factory, Certificate certificate, BigInteger d) throws Exception
        {
            // извлечь открытый ключ
            IPublicKey publicKey = certificate.getPublicKey(factory); 

            // получить параметры ключа
            aladdin.capi.gost.gostr3410.IECParameters parameters = 
                (aladdin.capi.gost.gostr3410.IECParameters)publicKey.parameters(); 

            // вернуть личный ключ
            return new aladdin.capi.gost.gostr3410.ECPrivateKey(
                factory, null, publicKey.keyOID(), parameters, d
            ); 
        }
        private static void test(Factory factory, 
            PfxContainer container, String testCertificateBase64, 
            Object testPrivateKeyObj, byte[] keyID) throws Exception
        {       
            // найти сертификат
            PfxSafeBag certItem = container.findCertificate(keyID); 

            // проверить наличие сертификата
            if (certItem == null) throw new NoSuchElementException();

            // извлечь содержимое сертификата
            CertBag certBag = new CertBag(certItem.decoded().bagValue()); 

            // раскодировать сертификат
            Certificate certificate = new Certificate(certBag.certValue().content()); 

            // указать сертификат для сравнения
            Certificate testCertificate = getCertificate(testCertificateBase64); 

            // сравнить сертификаты
            if (!certificate.equals(testCertificate)) throw new IllegalArgumentException(); 

            // найти личный ключ
            PfxSafeBag itemPrivateKey = container.findPrivateKey(keyID);

            // проверить наличие ключа
            if (itemPrivateKey == null) throw new NoSuchElementException(); 

            // извлечь содержимое сертификата
            PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(itemPrivateKey.decoded().bagValue()); 
            
            // при указании закодированного представленич
            if (testPrivateKeyObj instanceof PrivateKeyInfo)
            {
                // сравнить представления
                if (!privateKeyInfo.equals(testPrivateKeyObj)) throw new IllegalArgumentException();
            }
            // раскодировать ключ
            else try (IPrivateKey privateKey = factory.decodePrivateKey(privateKeyInfo))            
            {
                // извлечь секретное значение
                BigInteger d = ((aladdin.capi.gost.gostr3410.IECPrivateKey)privateKey).getS(); 
                    
                // сравнить личные ключи
                if (!d.equals(testPrivateKeyObj)) throw new IllegalArgumentException();
            }
        }
        // выполнить тест
        public static void testSignedEnveloped(Factory factory, 
            String containerBase64, String senderCertificateBase64, 
            BigInteger senderPrivateKeyD, String recipientCertificateBase64, 
            BigInteger recipientPrivateKeyD, String testCertificateBase64, 
            BigInteger testPrivateKeyD, byte[] keyID) throws Exception
        {
            // получить закодированный контейнер
            PFX pfx = new PFX(Encodable.decode(Base64.getDecoder().decode(containerBase64)));

            // указать генекатор случайных данных
            try (IRand rand = new aladdin.capi.Rand(null))
            {
                // раскодировать контейнер
                try (PfxSignedEnvelopedContainer container = new PfxSignedEnvelopedContainer(pfx, rand)) 
                {
                    // раскодировать сертификаты
                    Certificate senderCertificate    = getCertificate(senderCertificateBase64   ); 
                    Certificate recipientCertificate = getCertificate(recipientCertificateBase64); 

                    // извлечь личный ключ
                    try (IPrivateKey senderPrivateKey = getPrivateKey(
                        factory, senderCertificate, senderPrivateKeyD)) 
                    {
                        // извлечь личный ключ
                        try (IPrivateKey recipientPrivateKey = getPrivateKey(
                            factory, recipientCertificate, recipientPrivateKeyD))
                        {
                            // установить ключи
                            container.setSignKeys    (senderPrivateKey   , senderCertificate);
                            container.setEnvelopeKeys(recipientPrivateKey, recipientCertificate, null); 
                        }
                    }
                    // выполнить тест
                    test(factory, container, testCertificateBase64, testPrivateKeyD, keyID); 
                }
            }
        }
        // выполнить тест
        public static void testAuthenticatedEncrypted(Factory factory, 
            String containerBase64, String testCertificateBase64, 
            Object testPrivateKeyObj, byte[] keyID) throws Exception
        {
            // получить закодированный контейнер
            PFX pfx = new PFX(Encodable.decode(Base64.getDecoder().decode(containerBase64)));
            
            // указать генекатор случайных данных
            try (IRand rand = new aladdin.capi.Rand(null))
            {
                // раскодировать контейнер
                try (PfxAuthenticatedEncryptedContainer container = 
                    new PfxAuthenticatedEncryptedContainer(pfx, factory, rand)) 
                {
                    // указать пароль на контейнер
                    container.setPassword("Пароль для PFX");

                    // выполнить тест
                    test(factory, container, testCertificateBase64, testPrivateKeyObj, keyID); 
                }
            }
        }
        public static void test(Factory factory) throws Exception
        {
            getCertificate(
                "MIIBfTCCASqgAwIBAgIBADAKBgYqhQMCAgMFADA3MQswCQYDVQQGEwJSVTEoMCYG" + 
                "A1UEAwwfQ0EgY2VydGlmaWNhdGUgKFBLQ1MxMiBleGFtcGxlKTAeFw0xMjA2MTQx" + 
                "MzEyMzFaFw0xNzA2MTQxMzEyMzFaMDcxCzAJBgNVBAYTAlJVMSgwJgYDVQQDDB9D" + 
                "QSBjZXJ0aWZpY2F0ZSAoUEtDUzEyIGV4YW1wbGUpMGMwHAYGKoUDAgITMBIGByqF" + 
                "AwICIwEGByqFAwICHgEDQwAEQHxF7QOkGNDlnKWiBwdD80gToowegPcHR1Y1r2ZR" + 
                "RQqB610f3uEWN/EikI7exYVRR0dmCyILLMmgRxX+KU4qmgejHTAbMAwGA1UdEwQF" + 
                "MAMBAf8wCwYDVR0PBAQDAgEGMAoGBiqFAwICAwUAA0EAFnvKPRo2tQkI/iqu/CkP" + 
                "YQJPW43KnRMqkmB/NnGOC5+wdivIA5yJaGbT2sQ1r+n6qyJnG32yV44DrSe7b2DV" + 
                "OA=="
            ); 
            getCertificate(
                "MIICvjCCAmmgAwIBAgIQAdBoXvL8TSAAAAALJwkAATAMBggqhQMHAQEDAgUAMGAx" + 
                "CzAJBgNVBAYTAlJVMRUwEwYDVQQHDAzQnNC+0YHQutCy0LAxDzANBgNVBAoMBtCi" + 
                "0JoyNjEpMCcGA1UEAwwgQ0EgY2VydGlmaWNhdGUgKFBLQ1MjMTIgZXhhbXBsZSkw" + 
                "HhcNMTUwMzI3MDcyMzAwWhcNMjAwMzI3MDcyMzAwWjBgMQswCQYDVQQGEwJSVTEV" + 
                "MBMGA1UEBwwM0JzQvtGB0LrQstCwMQ8wDQYDVQQKDAbQotCaMjYxKTAnBgNVBAMM" + 
                "IENBIGNlcnRpZmljYXRlIChQS0NTIzEyIGV4YW1wbGUpMGYwHwYIKoUDBwEBAQEw" + 
                "EwYHKoUDAgIjAQYIKoUDBwEBAgIDQwAEQBxYC72z7PQOLZCzWEliXy7kNPks570v" + 
                "ENM2iUsWGwC0pk37mkGFBUmfkl3VkJamjlCzr/v/Ab49c/GcCqJap2eBCQAyNzA5" + 
                "MDAwMYIJADI3MDkwMDAxo4HfMIHcMA4GA1UdDwEB/wQEAwIBxjAPBgNVHRMBAf8E" + 
                "BTADAQH/MB0GA1UdDgQWBBQmnc7Xh5ykb5t/BMwOkxA4drfEmjCBmQYDVR0jBIGR" + 
                "MIGOgBQmnc7Xh5ykb5t/BMwOkxA4drfEmqFkpGIwYDELMAkGA1UEBhMCUlUxFTAT" + 
                "BgNVBAcMDNCc0L7RgdC60LLQsDEPMA0GA1UECgwG0KLQmjI2MSkwJwYDVQQDDCBD" + 
                "QSBjZXJ0aWZpY2F0ZSAoUEtDUyMxMiBleGFtcGxlKYIQAdBoXvL8TSAAAAALJwkA" + 
                "ATAMBggqhQMHAQEDAgUAA0EA++OazMpEpK+nTLytJKOYmr6RoeGtfSjXfUhLfsx8" + 
                "u1Jqzr9wEMK55pMNjMa8upPRiSmV8oZ+aw4ihq3Ltl8hfQ=="                
            ); 
            testSignedEnveloped(factory, 
                "MIIG9wIBAzCCBvAGCSqGSIb3DQEHAqCCBuEwggbdAgEBMQwwCgYGKoUDAgIJBQAw" + 
                "ggROBgkqhkiG9w0BBwGgggQ/BIIEOzCCBDcwggQzBgkqhkiG9w0BBwOgggQkMIIE" + 
                "IAIBADGCAQ4wggEKAgEAMD0wNzELMAkGA1UEBhMCUlUxKDAmBgNVBAMMH0NBIGNl" + 
                "cnRpZmljYXRlIChQS0NTMTIgZXhhbXBsZSkCAgEgMBwGBiqFAwICEzASBgcqhQMC" + 
                "AiQABgcqhQMCAh4BBIGnMIGkMCgEIAGMe6IJ3eXR1pyr+xM15mY82dhNVBQUrJuE" + 
                "ZbFnqnV6BARFro2ZoHgGByqFAwICHwGgYzAcBgYqhQMCAhMwEgYHKoUDAgIkAAYH" + 
                "KoUDAgIeAQNDAARAAMjagM5tZaUi0eIW9Fzy5KOOFLXxaOiYvDl3hVQgyqtZaNdL" + 
                "JMVYCcp6BSsEwJzQdKtnVQsYucsrJkI4USM6twQILd4b1Osjv1YwggMHBgkqhkiG" + 
                "9w0BBwEwHQYGKoUDAgIVMBMECO5jVyCHNqshBgcqhQMCAh8BgIIC2fsgXMb2pLM/" + 
                "bARkShmJgKENv9rlfvhAfxDF+zrVpoX6zBJTmOENQR+yGcsSpMWS8iByLIaIs47I" + 
                "V/ZC/1tYxSaAi3gchNiS4GlnEQI1Qe/raYF3j8XuMT/hPfxijMT68xB92s/oAqH0" + 
                "Mf/vrBj6fonF6Qjm8KkL3xz0sQKt+WFY/iI9HWYXm9zmJVxQ2SN4S5qacYm+SaNY" + 
                "DE+Vu+gZtfT0tPBRMC1GdB1MjKzvPA9ETfE0Cby99E46gYrUYRQXiUs6slH7En+M" + 
                "BVK0G8R8Q7lbo1H/NGXce2WS0Qll09ACz485TY85EHw8I9xCAFKWwk0wIjl+DuaF" + 
                "46YKA/DmbrhMPCOl53thXYt4lzttcBsyRKeDsEBVolBxNmkXlSQa3Wyq3WPefNth" + 
                "6cTbSK7Xybrm5QPHtxVQaWLYq4b6qsMt9aQC6s4tw7EoInJ/lEQTRF0Xgrbogl4l" + 
                "aTdaoiwV/x5kF33+yffgnVR1GNbIz6J94CQwSE9Y/XWJ/gibCdyahXkKn3q+88L/" + 
                "7ov9WGcdCZ59oTCmhOcyqSTYIKhPndO2lbIXCacKtAygAJVskTauGHZ2WlT4nRx0" + 
                "PdXfd0AqHkLjRRK3Veu0pNQtW+itHyxJJgECPEKwBdV40I1HQoR7qxo6YmLCK4Ey" + 
                "awNro32rw19iyyDb3MUTVg4ks2QtkEwBFCqsC3LTN2TViUsRJKxo7D9K517q0mZS" + 
                "T1LVnUr0DglwYEE2riDPMhBrzOWGPHO83HUfATr3lxKSbQOEpumQTuAgp4w8X0tY" + 
                "g/QZe501YL/v2VwJmAWNYaGFy6/o9Txyhy3KGtTqmWKIy4kChPYYM0CA1Bi4zm1X" + 
                "yWI7dSKhdBSfImWGEiXpV99AnK3v05Q+UGSPwM9ZrPNzyklfsd2cWVzJn2d7jz/D" + 
                "1RNRFnm1tHOkb7TDLXXZOUmtCftV2EDDyoNawzzyMj3Dax9WqibdU4TF1XQS0Mjz" + 
                "IqCCAYcwggGDMIIBMKADAgECAgIBHzAKBgYqhQMCAgMFADA3MQswCQYDVQQGEwJS" + 
                "VTEoMCYGA1UEAwwfQ0EgY2VydGlmaWNhdGUgKFBLQ1MxMiBleGFtcGxlKTAeFw0x" + 
                "MjA2MTQxMzIzMjVaFw0xNzA2MTQxMzIzMjVaMD8xCzAJBgNVBAYTAlJVMTAwLgYD" + 
                "VQQDDCdQRlgtaXNzdWVyIGNlcnRpZmljYXRlIChQS0NTMTIgZXhhbXBsZSkwYzAc" + 
                "BgYqhQMCAhMwEgYHKoUDAgIjAQYHKoUDAgIeAQNDAARAwAG9ZjvGxcd75HBztpMq" + 
                "U1EnQioI/kNh8q+sfotGqhTeKqoCgkQM9ZKRco/r97l55wRkTUvmH7cQL+xlvf7g" + 
                "16MaMBgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAwCgYGKoUDAgIDBQADQQBa7s+a" + 
                "arQxyzvAbQjsLhRq8+J/CN5CJkrIsJqC+XsjtqAkTaASRjYlLnqa2kBlcj6m+wJz" + 
                "id5g3AuyiqFJ/3JxMYHsMIHpAgEBMD0wNzELMAkGA1UEBhMCUlUxKDAmBgNVBAMM" + 
                "H0NBIGNlcnRpZmljYXRlIChQS0NTMTIgZXhhbXBsZSkCAgEfMAoGBiqFAwICCQUA" + 
                "oEswGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAvBgkqhkiG9w0BCQQxIgQg54zs" + 
                "FimpJAw5HrFrkRk33mtnqSIefxWYpqF1/a6jDJMwCgYGKoUDAgITBQAEQC40g80b" + 
                "nTSh3xEjk45Ml30Es2QlZemwrpLgM/35NRZ5WFii0QBwZopHdmhwXnnZftVnxCFN" + 
                "G3iM4SEARe4NoGY=",                 
                "MIIBgzCCATCgAwIBAgICAR8wCgYGKoUDAgIDBQAwNzELMAkGA1UEBhMCUlUxKDAm" + 
                "BgNVBAMMH0NBIGNlcnRpZmljYXRlIChQS0NTMTIgZXhhbXBsZSkwHhcNMTIwNjE0" + 
                "MTMyMzI1WhcNMTcwNjE0MTMyMzI1WjA/MQswCQYDVQQGEwJSVTEwMC4GA1UEAwwn" + 
                "UEZYLWlzc3VlciBjZXJ0aWZpY2F0ZSAoUEtDUzEyIGV4YW1wbGUpMGMwHAYGKoUD" + 
                "AgITMBIGByqFAwICIwEGByqFAwICHgEDQwAEQMABvWY7xsXHe+Rwc7aTKlNRJ0Iq" + 
                "CP5DYfKvrH6LRqoU3iqqAoJEDPWSkXKP6/e5eecEZE1L5h+3EC/sZb3+4NejGjAY" + 
                "MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgWgMAoGBiqFAwICAwUAA0EAWu7Pmmq0Mcs7" + 
                "wG0I7C4UavPifwjeQiZKyLCagvl7I7agJE2gEkY2JS56mtpAZXI+pvsCc4neYNwL" + 
                "soqhSf9ycQ==", new BigInteger(1, new byte[] { 
                    (byte)0xF9, (byte)0xFC, (byte)0x71, (byte)0x08, 
                    (byte)0xD1, (byte)0x4A, (byte)0xA6, (byte)0x2B, 
                    (byte)0xF0, (byte)0x13, (byte)0xC4, (byte)0x9E, 
                    (byte)0x6C, (byte)0xAE, (byte)0xF7, (byte)0x98, 
                    (byte)0xCA, (byte)0x0C, (byte)0x1D, (byte)0xEC, 
                    (byte)0xFA, (byte)0x73, (byte)0x19, (byte)0x00, 
                    (byte)0x1F, (byte)0xB2, (byte)0xF3, (byte)0x74, 
                    (byte)0xA3, (byte)0x3C, (byte)0xCA, (byte)0x50        
                }), 
                "MIIBhTCCATKgAwIBAgICASAwCgYGKoUDAgIDBQAwNzELMAkGA1UEBhMCUlUxKDAm" + 
                "BgNVBAMMH0NBIGNlcnRpZmljYXRlIChQS0NTMTIgZXhhbXBsZSkwHhcNMTIwNjE0" + 
                "MTMyNzA0WhcNMTcwNjE0MTMyNzA0WjBBMQswCQYDVQQGEwJSVTEyMDAGA1UEAwwp" + 
                "UEZYLXJlY2VpdmVyIGNlcnRpZmljYXRlIChQS0NTMTIgZXhhbXBsZSkwYzAcBgYq" + 
                "hQMCAhMwEgYHKoUDAgIkAAYHKoUDAgIeAQNDAARA2/9UcsvhgzpC4rlrJ9DNe5P5" + 
                "gCjFLbxRUdZOCaGjgvQH8nPk7ueKfavqyzEHRykmiVdsY6cAsEiQdH/1TB/j7aMa" + 
                "MBgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAwCgYGKoUDAgIDBQADQQA2cxOriZ+m" + 
                "RN8F66WxqonkJv7P7u86BOdMg7qGESqZIOOwoXJ4QMkDysM7jLElQ8ofR1zEPL4K" + 
                "lJbyu48wZWpZ", new BigInteger(1, new byte[] { 
                    (byte)0x0F, (byte)0xF5, (byte)0x46, (byte)0xD3, 
                    (byte)0x53, (byte)0x5C, (byte)0x04, (byte)0x5F, 
                    (byte)0xED, (byte)0x56, (byte)0x2B, (byte)0x0C, 
                    (byte)0xF9, (byte)0xD1, (byte)0x10, (byte)0xE2, 
                    (byte)0x9E, (byte)0x5D, (byte)0x64, (byte)0x21, 
                    (byte)0x16, (byte)0xE0, (byte)0x1E, (byte)0xA0, 
                    (byte)0x0E, (byte)0xE0, (byte)0x2A, (byte)0xF3, 
                    (byte)0xD4, (byte)0x88, (byte)0x70, (byte)0xF3
                }), 
                "MIIBfTCCASqgAwIBAgICASIwCgYGKoUDAgIDBQAwNzELMAkGA1UEBhMCUlUxKDAm" + 
                "BgNVBAMMH0NBIGNlcnRpZmljYXRlIChQS0NTMTIgZXhhbXBsZSkwHhcNMTIwNjE0" + 
                "MTkzMDE5WhcNMTcwNjE0MTkzMDE5WjA5MQswCQYDVQQGEwJSVTEqMCgGA1UEAwwh" + 
                "VGVzdCBjZXJ0aWZpY2F0ZSAoUEtDUzEyIGV4YW1wbGUpMGMwHAYGKoUDAgITMBIG" + 
                "ByqFAwICIwEGByqFAwICHgEDQwAEQHlSMCMAJZgoHUCIFmn+eqOgYlQy8h7SfjZ2" + 
                "kMkJ4xTae8jtZYxHLq3P+qJeismsHdmqdqSBbOGGdOaJNNPbAZKjGjAYMAkGA1Ud" + 
                "EwQCMAAwCwYDVR0PBAQDAgWgMAoGBiqFAwICAwUAA0EArslfUeqhW9eFkspn89+C" + 
                "OQEJX6JoghiOjFYlky0XmaaDl3D6EcbID+B6cBEmcXF21xxIEeYJIAqGzOEnMXdT" + 
                "cg==", new BigInteger(1, new byte[] { 
                    (byte)0xC9, (byte)0x0D, (byte)0x4A, (byte)0x60, 
                    (byte)0x74, (byte)0x4B, (byte)0x6E, (byte)0xF9, 
                    (byte)0xDD, (byte)0xB1, (byte)0xF1, (byte)0xD5, 
                    (byte)0xE2, (byte)0x34, (byte)0xF0, (byte)0x6C, 
                    (byte)0xEF, (byte)0x73, (byte)0x74, (byte)0x52, 
                    (byte)0x2D, (byte)0x03, (byte)0x91, (byte)0x89, 
                    (byte)0xD9, (byte)0x2E, (byte)0x82, (byte)0xDD, 
                    (byte)0xCF, (byte)0x41, (byte)0x14, (byte)0x16
                }), new byte[] {
                    (byte)0xE1, (byte)0x8B, (byte)0xEF, (byte)0x4B, 
                    (byte)0x1D, (byte)0xDC, (byte)0x5A, (byte)0x0A, 
                    (byte)0xF2, (byte)0x3A, (byte)0xC4, (byte)0x43, 
                    (byte)0xD9, (byte)0x8A, (byte)0xED, (byte)0x8C, 
                    (byte)0x23, (byte)0x48, (byte)0x9C, (byte)0xB4, 
                    (byte)0x00, (byte)0x79, (byte)0x36, (byte)0x3B, 
                    (byte)0x8A, (byte)0xE5, (byte)0xB6, (byte)0x23, 
                    (byte)0x73, (byte)0x0D, (byte)0xDE, (byte)0x32            
                } 
            );
            testAuthenticatedEncrypted(factory, 
                "MIIEEwIBAzCCA7QGCSqGSIb3DQEHAaCCA6UEggOhMIIDnTCCARgGCSqGSIb3DQEH" + 
                "AaCCAQkEggEFMIIBATCB/gYLKoZIhvcNAQwKAQKggbswgbgwbQYJKoZIhvcNAQUN" + 
                "MGAwPwYJKoZIhvcNAQUMMDIEILpuGiK13MTTYcljCu+3p9L4lD9QUcidf0uomBH8" + 
                "p0X4AgIH0DAKBgYqhQMCAgoFADAdBgYqhQMCAhUwEwQIlipveMPIIywGByqFAwIC" + 
                "HwEER3OFKLu/W8vuxRmlxBKaanNMKP5OCR9/i4unqEeUdzbfEk4Xp1w+9WVc+2JF" + 
                "SY2mXnoGq5VGjsZvS/HqkouBHx4k2ZtZ2ga0MTEwLwYJKoZIhvcNAQkVMSIEIOGL" + 
                "70sd3FoK8jrEQ9mK7YwjSJy0AHk2O4rltiNzDd4yMIICfQYJKoZIhvcNAQcGoIIC" + 
                "bjCCAmoCAQAwggJjBgkqhkiG9w0BBwEwbQYJKoZIhvcNAQUNMGAwPwYJKoZIhvcN" + 
                "AQUMMDIEIL++UYUsz7L3OZRulyPkAhjE+CKEuZrPVhSI/j+3qftJAgIH0DAKBgYq" + 
                "hQMCAgoFADAdBgYqhQMCAhUwEwQIa1W2aiLTw1IGByqFAwICHwGAggHlVy8Z1gHf" + 
                "3syYkTYwJcYvvX0/kUlSRlJtvgzJGrQkRUVAisIaL2eNmoGvb3tBuGFQyVT3XBJR" + 
                "mSJU8m7JM/Ywm6ISZ86FvNKCpuEQdhWqqaTeSW6PCwYblT3597p+wBr8o78rs9XU" + 
                "RVkiBFGKhdxFBzX67WiZE8suKAEPbEcQcqKRhc6rOCq30KZoohxzm5egLf04ADfS" + 
                "LCp7aLZoL+ZOPXHi4zDvguJVYaSRZAx8H9Du/pfdxWYUAgBYWF7j3w1Rr7e4R2pl" + 
                "0yb8Ssb18FqqAg0i5y8y6e4QdhHNsxkhAJpDnWU9GySjz/QtmrODq6S7vVLbvxN3" + 
                "lBEOnbqeKObfeMfTMtw1QnQq4To+18DZD/x215ks9hxbyDAwAJ0gBcHzk59e2Mll" + 
                "Nmd1rX7h7F5RAOahj6afVb36UgYZzjrzQvxWbasNobTKnetpjqyE6wk8IVJH1JDa" + 
                "/lV8njzst+7qWxaJQY4ZHb/XAZ1D3iLQAbNz9vxV2ZgQiEd4wYAJH5NyQu4yAtLI" + 
                "pyUQd0E5RRG68746cRsH7Y0JBc1tdeelSynqU7CJBlixe6ltD4eieD9cNxQNgsJ+" + 
                "3ixH9p2fHXhJ6X8cKv5vxR9twGv/gp+CD7hqb+OYms21Bq/DBeMmwHpkSqAJG+Aw" + 
                "VjAuMAoGBiqFAwICCQUABCDY1/8wm16eIez/P047eu7pkmfxjC7v5l7w9poiOrvJ" + 
                "mQQgyCOpfWCBX3nkoEVUA1uMXFC5vcUaf/mLm05x/S7fyTACAgfQ", 
                "MIIBfTCCASqgAwIBAgICASIwCgYGKoUDAgIDBQAwNzELMAkGA1UEBhMCUlUxKDAm" + 
                "BgNVBAMMH0NBIGNlcnRpZmljYXRlIChQS0NTMTIgZXhhbXBsZSkwHhcNMTIwNjE0" + 
                "MTkzMDE5WhcNMTcwNjE0MTkzMDE5WjA5MQswCQYDVQQGEwJSVTEqMCgGA1UEAwwh" + 
                "VGVzdCBjZXJ0aWZpY2F0ZSAoUEtDUzEyIGV4YW1wbGUpMGMwHAYGKoUDAgITMBIG" + 
                "ByqFAwICIwEGByqFAwICHgEDQwAEQHlSMCMAJZgoHUCIFmn+eqOgYlQy8h7SfjZ2" + 
                "kMkJ4xTae8jtZYxHLq3P+qJeismsHdmqdqSBbOGGdOaJNNPbAZKjGjAYMAkGA1Ud" + 
                "EwQCMAAwCwYDVR0PBAQDAgWgMAoGBiqFAwICAwUAA0EArslfUeqhW9eFkspn89+C" + 
                "OQEJX6JoghiOjFYlky0XmaaDl3D6EcbID+B6cBEmcXF21xxIEeYJIAqGzOEnMXdT" + 
                "cg==", new BigInteger(1, new byte[] { 
                    (byte)0xC9, (byte)0x0D, (byte)0x4A, (byte)0x60, 
                    (byte)0x74, (byte)0x4B, (byte)0x6E, (byte)0xF9, 
                    (byte)0xDD, (byte)0xB1, (byte)0xF1, (byte)0xD5, 
                    (byte)0xE2, (byte)0x34, (byte)0xF0, (byte)0x6C, 
                    (byte)0xEF, (byte)0x73, (byte)0x74, (byte)0x52, 
                    (byte)0x2D, (byte)0x03, (byte)0x91, (byte)0x89, 
                    (byte)0xD9, (byte)0x2E, (byte)0x82, (byte)0xDD, 
                    (byte)0xCF, (byte)0x41, (byte)0x14, (byte)0x16
                }), new byte[] {
                    (byte)0xE1, (byte)0x8B, (byte)0xEF, (byte)0x4B, 
                    (byte)0x1D, (byte)0xDC, (byte)0x5A, (byte)0x0A, 
                    (byte)0xF2, (byte)0x3A, (byte)0xC4, (byte)0x43, 
                    (byte)0xD9, (byte)0x8A, (byte)0xED, (byte)0x8C, 
                    (byte)0x23, (byte)0x48, (byte)0x9C, (byte)0xB4, 
                    (byte)0x00, (byte)0x79, (byte)0x36, (byte)0x3B, 
                    (byte)0x8A, (byte)0xE5, (byte)0xB6, (byte)0x23, 
                    (byte)0x73, (byte)0x0D, (byte)0xDE, (byte)0x32            
                }
            ); 
            {
                // получить закодированное представление
                byte[] encodedPrivateKeyInfo = Base64.getDecoder().decode(
                    "MGYCAQAwHwYIKoUDBwEBAQEwEwYHKoUDAgIjAQYIKoUDBwEBAgIEQEYbRu86z+1JFKDcPDN9UbTG" +
                    "G2ki9enTqos4KpUU0j9IDpl1UXiaA1YDIwUjlAp+81GkLmyt8Fw6Gt/X5JZySAY="
                ); 
                // извлечь описание личного ключа
                PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(
                    Encodable.decode(encodedPrivateKeyInfo)
                ); 
                // выполнить тест
                testAuthenticatedEncrypted(factory, 
                    "MIIFqgIBAzCCBSsGCSqGSIb3DQEHAaCCBRwEggUYMIIFFDCCASIGCSqGSIb3DQEH" + 
                    "AaCCARMEggEPMIIBCzCCAQcGCyqGSIb3DQEMCgECoIHgMIHdMHEGCSqGSIb3DQEF" + 
                    "DTBkMEEGCSqGSIb3DQEFDDA0BCD5qZr0TTIsBvdgUoq/zFwOzdyJohj6/4Wiyccg" + 
                    "j9AK/QICB9AwDAYIKoUDBwEBBAIFADAfBgYqhQMCAhUwFQQI3Ip/Vp0IsyIGCSqF" + 
                    "AwcBAgUBAQRoSfLhgx9s/zn+BjnhT0ror07vS55Ys5hgvVpWDx4mXGWWyez/2sMc" + 
                    "aFgSr4H4UTGGwoMynGLpF1IOVo+bGJ0ePqHB+gS5OL9oV+PUmZ/ELrRENKlCDqfY" + 
                    "WvpSystX29CvCFrnTnDsbBYxFTATBgkqhkiG9w0BCRUxBgQEAQAAADCCA+oGCSqG" + 
                    "SIb3DQEHBqCCA9swggPXAgEAMIID0AYJKoZIhvcNAQcBMHEGCSqGSIb3DQEFDTBk" + 
                    "MEEGCSqGSIb3DQEFDDA0BCCJTJLZQRi1WIpQHzyjXbq7+Vw2+1280C45x8ff6kMS" + 
                    "VAICB9AwDAYIKoUDBwEBBAIFADAfBgYqhQMCAhUwFQQIxepowwvS11MGCSqFAwcB" + 
                    "AgUBAYCCA06n09P/o+eDEKoSWpvlpOLKs7dKmVquKzJ81nCngvLQ5fEWL1WkxwiI" + 
                    "rEhm53JKLD0wy4hekalEk011Bvc51XP9gkDkmaoBpnV/TyKIY35wl6ATfeGXno1M" + 
                    "KoA+Ktdhv4gLnz0k2SXdkUj11JwYskXue+REA0p4m2ZsoaTmvoODamh9JeY/5Qjy" + 
                    "Xe58CGnyXFzX3eU86qs4WfdWdS3NzYYOk9zzVl46le9u79O/LnW2j4n2of/Jpk/L" + 
                    "YjrRmz5oYeQOqKOKhEyhpO6e+ejr6laduEv7TwJQKRNiygogbVvkNn3VjHTSOUG4" + 
                    "W+3NRPhjb0jD9obdyx6MWa6O3B9bUzFMNav8/gYn0vTDxqXMLy/92oTngNrVx6Gc" + 
                    "cNl128ISrDS6+RxtAMiEBRK6xNkemqX5yNXG5GrLQQFGP6mbs2nNpjKlgj3pljmX" + 
                    "Eky2/G78XiJrv02OgGs6CKnI9nMpa6N7PBHV34MJ6EZzWOWDRQ420xk63mnicrs0" + 
                    "WDVJ0xjdu4FW3iEk02EaiRTvGBpa6GL7LBp6QlaXSSwONx725cyRsL9cTlukqXER" + 
                    "WHDlMpjYLbkGZRrCc1myWgEfsputfSIPNF/oLv9kJNWacP3uuDOfecg3us7eg2OA" + 
                    "xo5zrYfn39GcBMF1WHAYRO/+PnJb9jrDuLAE8+ONNqjNulWNK9CStEhb6Te+yE6q" + 
                    "oeP6hJjFLi+nFLE9ymIo0A7gLQD5vzFvl+7v1ZNVnQkwRUsWoRiEVVGnv3Z1iZU6" + 
                    "xStxgoHMl62V/P5cz4dr9vJM2adEWNZcVXl6mk1H8DRc1sRGnvs2l237oKWRVntJ" + 
                    "hoWnZ8qtD+3ZUqsX79QhVzUQBzKuBt6jwNhaHLGl5B+Or/zA9FezsOh6+Uc+fZaV" + 
                    "W7fFfeUyWwGy90XD3ybTrjzep9f3nt55Z2c+fu2iEwhoyImWLuC3+CVhf9Af59j9" + 
                    "8/BophMJuATDJEtgi8rt4vLnfxKu250Mv2ZpbfF69EGTgFYbwc55zRfaUG9zlyCu" + 
                    "1YwMJ6HC9FUVtJp9gObSrirbzTH7mVaMjQkBLotazWbegzI+be8V3yT06C+ehD+2" + 
                    "GdLWAVs9hp8gPHEUShb/XrgPpDSJmFlOiyeOFBO/j4edDACKqVcwdjBOMAoGCCqF" + 
                    "AwcBAQIDBEAIFX0fyZe20QKKhWm6WYX+S92Gt6zaXroXOvAmayzLfZ5Sd9C2t9zZ" + 
                    "JSg6M8RBUYpw/8ym5ou1o2nDa09M5zF3BCCpzyCQBI+rzfISeKvPV1ROfcXiYU93" + 
                    "mwcl1xQV2G5/fgICB9A=", 
                    "MIIDAjCCAq2gAwIBAgIQAdBoXzEflsAAAAALJwkAATAMBggqhQMHAQEDAgUAMGAx" + 
                    "CzAJBgNVBAYTAlJVMRUwEwYDVQQHDAzQnNC+0YHQutCy0LAxDzANBgNVBAoMBtCi" + 
                    "0JoyNjEpMCcGA1UEAwwgQ0EgY2VydGlmaWNhdGUgKFBLQ1MjMTIgZXhhbXBsZSkw" + 
                    "HhcNMTUwMzI3MDcyNTAwWhcNMjAwMzI3MDcyMzAwWjBkMQswCQYDVQQGEwJSVTEV" + 
                    "MBMGA1UEBwwM0JzQvtGB0LrQstCwMQ8wDQYDVQQKDAbQotCaMjYxLTArBgNVBAMM" + 
                    "JFRlc3QgY2VydGlmaWNhdGUgMSAoUEtDUyMxMiBleGFtcGxlKTBmMB8GCCqFAwcB" + 
                    "AQEBMBMGByqFAwICIwEGCCqFAwcBAQICA0MABEDXHPKaSm+vZ1glPxZM5fcO33r/" + 
                    "6Eaxc3K1RCmRYHkiYkzi2D0CwLhEhTBXkfjUyEbS4FEXB5PM3oCwB0G+FMKVgQkA" + 
                    "MjcwOTAwMDGjggEpMIIBJTArBgNVHRAEJDAigA8yMDE1MDMyNzA3MjUwMFqBDzIw" + 
                    "MTYwMzI3MDcyNTAwWjAOBgNVHQ8BAf8EBAMCBPAwHQYDVR0OBBYEFCFY6xFDrzJg" + 
                    "3ZS2D+jAehZyqxVtMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAMBgNV" + 
                    "HRMBAf8EAjAAMIGZBgNVHSMEgZEwgY6AFCadzteHnKRvm38EzA6TEDh2t8SaoWSk" + 
                    "YjBgMQswCQYDVQQGEwJSVTEVMBMGA1UEBwwM0JzQvtGB0LrQstCwMQ8wDQYDVQQK" + 
                    "DAbQotCaMjYxKTAnBgNVBAMMIENBIGNlcnRpZmljYXRlIChQS0NTIzEyIGV4YW1w" + 
                    "bGUpghAB0Ghe8vxNIAAAAAsnCQABMAwGCCqFAwcBAQMCBQADQQD2irRW+TySSAjC" + 
                    "SnTHQnl4q2Jrgw1OLAoCbuOCcJkjHc73wFOFpNfdlCESjZEv2lMI+vrAUyF54n5h" + 
                    "0YxF5e+y", privateKeyInfo, new byte[] { 0x01, 0x00, 0x00, 0x00 }
                );
            }
        }
    }
}

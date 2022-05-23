using System;
using System.Text;

namespace Aladdin.CAPI.GOST
{
    public class Test : CAPI.Test
    {
        public static void Entry()
        {
            using (GOST.Factory factory = new GOST.Factory()) 
            {
                SecurityStore scope = null; 

                CMS.Test(factory); 

                // идентификаторы наборов параметров
                string[] hashOIDs = new string[] {
                    ASN1.GOST.OID.hashes_test, ASN1.GOST.OID.hashes_cryptopro
                }; 
                // идентификаторы наборов параметров
                string[] sboxOIDs = new string[] {
                    ASN1.GOST.OID.encrypts_test, ASN1.GOST.OID.encrypts_A,
                    ASN1.GOST.OID.encrypts_B,    ASN1.GOST.OID.encrypts_C,     
                    ASN1.GOST.OID.encrypts_D,    ASN1.GOST.OID.encrypts_tc26_z
                }; 
                /////////////////////////////////////////////////////////////////////
                // Алгоритмы хэширования
                ////////////////////////////////////////////////////////////////////
                for (int i = 0; i < hashOIDs.Length; i++)
                {
                    TestGOSTR3411_1994(factory, scope, hashOIDs[i]); 
                }
                TestGOSTR3411_2012_256(factory, scope); 
                TestGOSTR3411_2012_512(factory, scope); 
            
                /////////////////////////////////////////////////////////////////////
                // Алгоритмы вычисления имитовставки
                ////////////////////////////////////////////////////////////////////
                for (int i = 0; i < sboxOIDs.Length; i++)
                {
                    TestMAC_GOST28147(factory, scope, sboxOIDs[i]); 
                }
                for (int i = 0; i < hashOIDs.Length; i++)
                {
                    TestHMAC_GOSTR3411_1994(factory, scope, hashOIDs[i]); 
                }
                TestHMAC_GOSTR3411_2012_256(factory, scope); 
                TestHMAC_GOSTR3411_2012_512(factory, scope); 
                TestMAC_GOSTR3412          (factory, scope);
        
                /////////////////////////////////////////////////////////////////////
                // Алгоритмы шифрования
                ////////////////////////////////////////////////////////////////////
                for (int i = 0; i < sboxOIDs.Length; i++)
                {
                    TestGOST28147(factory, scope, sboxOIDs[i]);                     
                }
                TestGOSTR3412(factory, scope); 
            
                /////////////////////////////////////////////////////////////////////
                // Алгоритмы наследования ключа
                ////////////////////////////////////////////////////////////////////
                TestPBKDF2_HMAC_GOST3411_94(factory, scope); 
                TestKDF_GOSTR3411_2012     (factory, scope); 
        
                // указать генератор случайных данных
                using (IRand rand = new CAPI.Rand(null))
                { 
                    /////////////////////////////////////////////////////////////////////
                    // ГОСТ Р 34.10
                    ////////////////////////////////////////////////////////////////////
                    int wrapFlags = 
                        Wrap.RFC4357.NoneSBoxA | Wrap.RFC4357.NoneSBoxB | 
                        Wrap.RFC4357.NoneSBoxC | Wrap.RFC4357.NoneSBoxD |
                        Wrap.RFC4357.CProSBoxA | Wrap.RFC4357.CProSBoxB | 
                        Wrap.RFC4357.CProSBoxC | Wrap.RFC4357.CProSBoxD; 

                    TestGOSTR3410_1994(factory, null); 
                    TestGOSTR3410_1994(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.signs_A, ASN1.GOST.OID.hashes_cryptopro, null, 0
                    ); 
                    TestGOSTR3410_1994(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.signs_B, ASN1.GOST.OID.hashes_cryptopro, null, 0
                    ); 
                    TestGOSTR3410_1994(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.signs_C, ASN1.GOST.OID.hashes_cryptopro, null, 0
                    ); 
                    TestGOSTR3410_1994(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.signs_D, ASN1.GOST.OID.hashes_cryptopro, null, 0
                    ); 
                    TestGOSTR3410_1994(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.exchanges_A, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_A, wrapFlags
                    ); 
                    TestGOSTR3410_1994(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.exchanges_A, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_B, wrapFlags
                    ); 
                    TestGOSTR3410_1994(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.exchanges_A, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_C, wrapFlags
                    ); 
                    TestGOSTR3410_1994(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.exchanges_A, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_D, wrapFlags
                    ); 
                    TestGOSTR3410_1994(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.exchanges_B, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_A, wrapFlags
                    ); 
                    TestGOSTR3410_1994(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.exchanges_B, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_B, wrapFlags
                    ); 
                    TestGOSTR3410_1994(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.exchanges_B, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_C, wrapFlags
                    ); 
                    TestGOSTR3410_1994(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.exchanges_B, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_D, wrapFlags
                    ); 
                    TestGOSTR3410_1994(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.exchanges_C, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_A, wrapFlags
                    ); 
                    TestGOSTR3410_1994(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.exchanges_C, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_B, wrapFlags
                    ); 
                    TestGOSTR3410_1994(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.exchanges_C, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_C, wrapFlags
                    ); 
                    TestGOSTR3410_1994(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.exchanges_C, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_D, wrapFlags
                    ); 

                    TestGOSTR3410_2001(factory, null); 
                    TestGOSTR3410_2001(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.ecc_signs_A, ASN1.GOST.OID.hashes_cryptopro, null, 0
                    ); 
                    TestGOSTR3410_2001(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.ecc_signs_B, ASN1.GOST.OID.hashes_cryptopro, null, 0
                    ); 
                    TestGOSTR3410_2001(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.ecc_signs_C, ASN1.GOST.OID.hashes_cryptopro, null, 0
                    ); 
                    TestGOSTR3410_2001(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.ecc_exchanges_A, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_A, wrapFlags 
                    ); 
                    TestGOSTR3410_2001(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.ecc_exchanges_A, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_B, wrapFlags 
                    ); 
                    TestGOSTR3410_2001(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.ecc_exchanges_A, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_C, wrapFlags 
                    ); 
                    TestGOSTR3410_2001(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.ecc_exchanges_A, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_D, wrapFlags 
                    ); 
                    TestGOSTR3410_2001(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.ecc_exchanges_B, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_A, wrapFlags
                    ); 
                    TestGOSTR3410_2001(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.ecc_exchanges_B, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_B, wrapFlags
                    ); 
                    TestGOSTR3410_2001(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.ecc_exchanges_B, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_C, wrapFlags
                    ); 
                    TestGOSTR3410_2001(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.ecc_exchanges_B, ASN1.GOST.OID.hashes_cryptopro, 
                        ASN1.GOST.OID.encrypts_D, wrapFlags
                    ); 

                    int[] keySizes = new int[] {32, 64}; 
                    wrapFlags = wrapFlags | Wrap.RFC4357.NoneSBoxZ | Wrap.RFC4357.CProSBoxZ; 

                    TestGOSTR3410_2012_256(factory, null); 
                    TestGOSTR3410_2012_256(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.ecc_signs_A, null, 0
                    ); 
                    TestGOSTR3410_2012_256(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.ecc_signs_B, null, 0
                    ); 
                    TestGOSTR3410_2012_256(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.ecc_signs_C, null, 0
                    ); 
                    TestGOSTR3410_2012_256(factory, scope, rand, true, KeyFlags.None, 
                        ASN1.GOST.OID.ecc_exchanges_A, keySizes, wrapFlags
                    ); 
                    TestGOSTR3410_2012_256(factory, scope, rand, true, KeyFlags.None,
                        ASN1.GOST.OID.ecc_exchanges_B, keySizes, wrapFlags
                    ); 
                    TestGOSTR3410_2012_256(factory, scope, rand, true, KeyFlags.None,
                        ASN1.GOST.OID.ecc_tc26_2012_256A, keySizes, wrapFlags
                    ); 

                    TestGOSTR3410_2012_512(factory, null, keySizes); 
                    TestGOSTR3410_2012_512(factory, scope, rand, true, KeyFlags.None,
                        ASN1.GOST.OID.ecc_tc26_2012_512A, keySizes, wrapFlags
                    ); 
                    TestGOSTR3410_2012_512(factory, scope, rand, true, KeyFlags.None,
                        ASN1.GOST.OID.ecc_tc26_2012_512B, keySizes, wrapFlags
                    ); 
                    TestGOSTR3410_2012_512(factory, scope, rand, true, KeyFlags.None,
                        ASN1.GOST.OID.ecc_tc26_2012_512C, keySizes, wrapFlags
                    ); 
                }
                /////////////////////////////////////////////////////////////////////
                // CMS/PKCS12
                ////////////////////////////////////////////////////////////////////
                CMS   .Test(factory); 
                PKCS12.Test(factory);
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Алгоритмы хэширования
        ////////////////////////////////////////////////////////////////////////////
        public static void TestGOSTR3411_1994(CAPI.Factory factory, SecurityStore scope, string hashOID)
        {
            WriteLine("Hash.GOSTR3411_1994/{0}", hashOID);
        
		    // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_94), new ASN1.ObjectIdentifier(hashOID)
            ); 
            // создать алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters)) 
            {
                if (hashOID == ASN1.GOST.OID.hashes_test)
                {
                    // выполнить тест
                    Hash.GOSTR3411_1994.TestTest(hashAlgorithm);
                }
                if (hashOID == ASN1.GOST.OID.hashes_cryptopro)
                {
                    // выполнить тест
                    Hash.GOSTR3411_1994.TestCPro(hashAlgorithm);
                }
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new GOST.Factory()) 
                {
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestGOSTR3411_2012_256(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Hash.GOSTR3411_2012_256");
        
		    // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_256), ASN1.Null.Instance
            ); 
            // создать алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters)) 
            {
                // выполнить тест
                Hash.GOSTR3411_2012.Test256(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new GOST.Factory()) 
                {
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestGOSTR3411_2012_512(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Hash.GOSTR3411_2012_512");
        
		    // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_512), ASN1.Null.Instance
            ); 
            // создать алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters)) 
            {
                // выполнить тест
                Hash.GOSTR3411_2012.Test512(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new GOST.Factory()) 
                {
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Алгоритмы вычисления имитовставки
        ////////////////////////////////////////////////////////////////////////////
        public static void TestMAC_GOST28147(CAPI.Factory factory, 
            SecurityStore scope, string sboxOID)
        {
            WriteLine("MAC.GOST28147/{0}", sboxOID);

		    // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gost28147_89_MAC), 
                new ASN1.GOST.GOST28147CipherParameters(
                    new ASN1.OctetString(new byte[8]), new ASN1.ObjectIdentifier(sboxOID)
                )
            ); 
            // создать алгоритм вычисления имитовставки
            using (Mac macAlgorithm = factory.CreateAlgorithm<Mac>(scope, parameters))
            { 
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new GOST.Factory()) 
                {
                    // указать допустимые размеры
                    int[] dataSizes = new int[] { 0, 1, 7, 8, 9, 15, 16, 17, 1023, 1024, 1025 }; 

                    // выполнить тест
                    MacTest(macAlgorithm, trustFactory, null, parameters, dataSizes); 
                }
            }
        }
        public static void TestHMAC_GOSTR3411_1994(
            CAPI.Factory factory, SecurityStore scope, string hashOID)
        {
            WriteLine("MAC.HMAC_GOSTR3411_1994/{0}", hashOID);

            // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_94_HMAC), new ASN1.ObjectIdentifier(hashOID)
            ); 
            // создать алгоритм вычисления имитовставки
            using (Mac macAlgorithm = factory.CreateAlgorithm<Mac>(scope, parameters))
            {
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new GOST.Factory()) 
                {
                    // указать допустимые размеры
                    int[] dataSizes = new int[] { 0, 1, 31, 32, 33 }; 

                    // выполнить тест
                    MacTest(macAlgorithm, trustFactory, null, parameters, dataSizes); 
                }
            }
        }
        public static void TestHMAC_GOSTR3411_2012_256(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("MAC.HMAC_GOSTR3411_2012_256");

            // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_HMAC_256), ASN1.Null.Instance
            ); 
            // создать алгоритм вычисления имитовставки
            using (Mac macAlgorithm = factory.CreateAlgorithm<Mac>(scope, parameters))
            {
                // выполнить тест
                Hash.GOSTR3411_2012.TestHMAC256(macAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new GOST.Factory()) 
                {
                    // указать допустимые размеры
                    int[] dataSizes = new int[] { 0, 1, 63, 64, 65 }; 

                    // выполнить тест
                    MacTest(macAlgorithm, trustFactory, null, parameters, dataSizes); 
                }
            }
        }    
        public static void TestHMAC_GOSTR3411_2012_512(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("MAC.HMAC_GOSTR3411_2012_512");
        
		    // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_HMAC_512), ASN1.Null.Instance
            ); 
            // создать алгоритм вычисления имитовставки
            using (Mac macAlgorithm = factory.CreateAlgorithm<Mac>(scope, parameters)) 
            {
                // выполнить тест
                Hash.GOSTR3411_2012.TestHMAC512(macAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new GOST.Factory()) 
                {
                    // указать допустимые размеры
                    int[] dataSizes = new int[] { 0, 1, 63, 64, 65 }; 

                    // выполнить тест
                    MacTest(macAlgorithm, trustFactory, null, parameters, dataSizes); 
                }
            }
        }    
        public static void TestMAC_GOSTR3412(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("MAC.GOSTR3412/64");

            // создать алгоритм шифрования блока
            using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                scope, "GOST3412_2015_M", ASN1.Null.Instance))
            {
                // выполнить тест
                Engine.GOSTR3412_M.TestMAC(blockCipher);
            }
            WriteLine(); 
            WriteLine("MAC.GOSTR3412/128");
        
            // создать алгоритм шифрования блока
            using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                scope, "GOST3412_2015_K", ASN1.Null.Instance))
            {
                // выполнить тест
                Engine.GOSTR3412_K.TestMAC(blockCipher);
            }
            Console.WriteLine(); 
        }
        ////////////////////////////////////////////////////////////////////////////
        // Алгоритмы шифрования
        ////////////////////////////////////////////////////////////////////////////
        public static void TestGOST28147(IBlockCipher blockCipher, String paramOID) 
        {
            // указать допустимые размеры
            int[] dataSizes = new int[] { 0, 1, 7, 8, 9, 15, 16, 17, 1023, 1024, 1025 }; 

            // указать доверенную фабрику
            using (GOST.Factory trustFactory = new GOST.Factory()) 
            {
                // указать генератор случайных данных
                using (IRand rand = new CAPI.Rand(null))
                {
                    // указать параметры алгоритма
                    ASN1.IEncodable paramSet = new ASN1.ObjectIdentifier(paramOID); 

                    // получить доверенный алгоритм шифрования
                    using (IBlockCipher trustBlockCipher = 
                        trustFactory.CreateAlgorithm<IBlockCipher>(null, "GOST28147", paramSet))
                    {
                        // указать режим ECB
                        CipherMode parameters = new CipherMode.ECB(); 

                        // создать режим шифрования
                        using (CAPI.Cipher trustCipher = trustBlockCipher.CreateBlockMode(parameters))
                        {
                            // создать режим шифрования
                            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(parameters))
                            {
                                // выполнить тест
                                if (paramOID == ASN1.GOST.OID.encrypts_tc26_z) Engine.GOST28147.TestZ(cipher);

                                // выполнить тест
                                CAPI.Cipher.CompatibleTest(rand, cipher, trustCipher, PaddingMode.PKCS5, dataSizes); 
                            }
                        }
                        // сгенерировать синхропосылку
                        byte[] iv = new byte[8]; Generate(iv, 0, iv.Length); 
                    
                        // указать режим CBC
                        parameters = new CipherMode.CBC(iv); 

                        // создать режим шифрования
                        using (CAPI.Cipher trustCipher = trustBlockCipher.CreateBlockMode(parameters))
                        {
                            // создать режим шифрования
                            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(parameters))
                            {
                                // выполнить тест
                                CAPI.Cipher.CompatibleTest(rand, cipher, trustCipher, PaddingMode.PKCS5, dataSizes); 
                            }
                        }
                        // указать режим CFB
                        rand.Generate(iv, 0, iv.Length); parameters = new CipherMode.CFB(iv, iv.Length); 

                        // создать режим шифрования
                        using (CAPI.Cipher trustCipher = trustBlockCipher.CreateBlockMode(parameters))
                        {
                            // создать режим шифрования
                            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(parameters))
                            {
                                // выполнить тест
                                CAPI.Cipher.CompatibleTest(rand, cipher, trustCipher, PaddingMode.None, dataSizes); 
                            }
                        }
                        // указать режим CTR
                        rand.Generate(iv, 0, iv.Length); parameters = new CipherMode.CTR(iv, iv.Length); 

                        // создать режим шифрования
                        using (CAPI.Cipher trustCipher = trustBlockCipher.CreateBlockMode(parameters))
                        {
                            // создать режим шифрования
                            using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(parameters))
                            {
                                // выполнить тест
                                CAPI.Cipher.CompatibleTest(rand, cipher, trustCipher, PaddingMode.None, dataSizes); 
                            }
                        }
                    }
                }
            }
        }
        public static void TestGOST28147(CAPI.Factory factory, SecurityStore scope, string paramOID)
        {
            WriteLine("Cipher.GOST28147/{0}", paramOID);
        
            // указать параметры алгоритма
            ASN1.IEncodable paramSet = new ASN1.ObjectIdentifier(paramOID); 
                
            // создать блочный алгоритм шифрования
            using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                scope, "GOST28147", paramSet))
            {
                // выполнить тесты
                if (blockCipher != null) TestGOST28147(blockCipher, paramOID); 
            }
            // указать допустимые размеры
            int[] dataSizes = new int[] { 0, 1, 7, 8, 9, 15, 16, 17, 1023, 1024, 1025 }; 

            // указать генератор случайных данных
            byte[] iv = new byte[8]; Generate(iv, 0, iv.Length); 

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gost28147_89), 
                new ASN1.GOST.GOST28147CipherParameters(
                    new ASN1.OctetString(iv), new ASN1.ObjectIdentifier(paramOID)
                )
            ); 
            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
            {
                // указать доверенную фабрику
                using (GOST.Factory trustFactory = new GOST.Factory()) 
                {
                    // выполнить тест
                    CipherTest(cipher, PaddingMode.None, trustFactory, null, parameters, dataSizes);
                }
            }
        }
        public static void TestGOSTR3412(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Cipher.GOSTR3412/64");
        
            // создать алгоритм шифрования блока
            using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                scope, "GOST3412_2015_M", ASN1.Null.Instance))
            {
                // протестировать алгоритм
                Engine.GOSTR3412_M.Test(blockCipher);
            }
            WriteLine();
            WriteLine("Cipher.GOSTR3412/128");
        
            // создать алгоритм шифрования блока
            using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                scope, "GOST3412_2015_K", ASN1.Null.Instance))
            {
                // протестировать алгоритм
                Engine.GOSTR3412_K.Test(blockCipher);
            }
            WriteLine();

            // протестировать алгоритм
            WriteLine("KeyWrap.KExp15/64");
            Wrap.KExp15.Test(factory, scope, 8);
            WriteLine();
        
            WriteLine("KeyWrap.KExp15/128");
            Wrap.KExp15.Test(factory, scope, 16);
            WriteLine();
        }
        ////////////////////////////////////////////////////////////////////////////
        // Алгоритмы наследования ключа
        ////////////////////////////////////////////////////////////////////////////
        public static void TestPBKDF2_HMAC_GOST3411_94(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("KeyDerive.PBKDF2_GOST3411_94");
        
            // выполнить тест
            Hash.GOSTR3411_1994.TestPBKDF2(factory, scope);
        }
        public static void TestKDF_GOSTR3411_2012(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("KeyDerive.KDF_GOSTR3411_2012");
        
		    // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_HMAC_256), ASN1.Null.Instance
            ); 
            // создать алгоритм вычисления имитовставки
            using (Mac macAlgorithm = factory.CreateAlgorithm<Mac>(scope, parameters)) 
            {
                // выполнить тест
                Derive.TC026.Test(macAlgorithm);
            }
        }    
        ////////////////////////////////////////////////////////////////////////////
        // ГОСТ P 34.10-1994
        ////////////////////////////////////////////////////////////////////////////
        public static void TestGOSTR3410_1994(CAPI.Factory factory, Container container)
        {
            WriteLine("GOSTR3410.1994");
        
            // закодировать параметры алгоритма подписи
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_1994), ASN1.Null.Instance
            );
            if (container != null)
            {
                // получить алгоритм выработки подписи
                using (SignHash signHash = container.Provider.CreateAlgorithm<SignHash>(
                    container.Store, parameters))
                try {
                    // выполнить тест
                    Sign.GOSTR3410.DHSignHash.Test(factory, container, signHash);
                }
                // удалить ключи из контейнера
                finally { container.DeleteKeys(); }

                // вывести сообщение
                Write("OK  "); 
            
                // получить алгоритм проверки подписи
                using (VerifyHash verifyHash = container.Provider.CreateAlgorithm<VerifyHash>(
                    container.Store, parameters))
                {
                    // выполнить тест
                    Sign.GOSTR3410.DHVerifyHash.Test(verifyHash);
                }
                // вывести сообщение
                Write("OK  "); 
            }
            else {
                // получить алгоритм выработки подписи
                using (SignHash signHash = factory.CreateAlgorithm<SignHash>(null, parameters))
                {
                    // выполнить тест
                    Sign.GOSTR3410.DHSignHash.Test(factory, container, signHash);
                }
                // вывести сообщение
                Write("OK  "); 
            
                // получить алгоритм проверки подписи
                using (VerifyHash verifyHash = factory.CreateAlgorithm<VerifyHash>(null, parameters))
                {
                    // выполнить тест
                    Sign.GOSTR3410.DHVerifyHash.Test(verifyHash);
                }
                // вывести сообщение
                Write("OK  "); 
            }
            WriteLine();
        }
        public static void TestGOSTR3410_1994(CAPI.Factory factory, SecurityObject scope, 
            IRand rand, bool generate, KeyFlags keyFlags, string paramOID, 
            string hashOID, string sboxOID, int wrapFlags)
        {
            // сформировать заголовок
            string header = String.Format("{0}/{1}", paramOID, hashOID); 
        
            // сформировать заголовок
            if (sboxOID != null) header = String.Format("{0}/{1}", header, sboxOID); 
        
            // вывести заголовок
            WriteLine("GOSTR3410.1994/{0}", header); 
            
            // указать идентификатор ключа
            string keyOID = ASN1.GOST.OID.gostR3410_1994; int[] keySizes = new int[] {32};  
        
            // указать доверенную фабрику
            using (CAPI.Factory trustFactory = new GOST.Factory()) 
            {
                // получить фабрику кодирования ключа
                KeyFactory keyFactory = trustFactory.GetKeyFactory(keyOID); 

                // указать способ использования ключа
                KeyUsage keyUsage = keyFactory.GetKeyUsage(); 

                // скорректировать способ использования ключа
                if (wrapFlags == 0) keyUsage = keyUsage & ~(KeyUsage.KeyEncipherment | KeyUsage.KeyAgreement);
                else { 
                    // скорректировать способ использования ключа
                    keyUsage = keyUsage & ~KeyUsage.DigitalSignature; 
                }
                // в зависимости от параметров
                ASN1.ObjectIdentifier encodedSBoxOID = null; if (sboxOID != null) 
                {
                    // закодировать таблицу подстановок
                    encodedSBoxOID = new ASN1.ObjectIdentifier(sboxOID); 
                }
                // закодировать параметры ключа
                ASN1.IEncodable encodedParameters = new ASN1.GOST.GOSTR3410PublicKeyParameters2001(
                    new ASN1.ObjectIdentifier(paramOID), 
                    new ASN1.ObjectIdentifier(hashOID), encodedSBoxOID
                ); 
                // раскодировать параметры алгоритма
                IParameters parameters = keyFactory.DecodeParameters(encodedParameters); 

                // сгенерировать ключевую пару
                using (KeyPair keyPair = GenerateKeyPair(
                    factory, scope, rand, trustFactory, null, generate, 
                    keyOID, parameters, keyUsage, keyFlags)) 
                try {
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.DigitalSignature) != KeyUsage.None)
                    { 
                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_94), 
                            new ASN1.ObjectIdentifier(hashOID) 
                        ); 
                        // указать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(keyOID), ASN1.Null.Instance
                        ); 
                        // указать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier signParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_94_R3410_1994), null
                        ); 
                        // выполнить тест
                        SignTest(trustFactory, null, hashParameters, 
                            signHashParameters, signParameters, keyPair, keyFlags 
                        );
                    }
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.KeyEncipherment) != KeyUsage.None)
                    { 
                        // указать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier transportParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(keyOID), ASN1.Null.Instance
                        ); 
                        // выполнить тест
                        TransportKeyTest(trustFactory, null, 
                            transportParameters, keyPair, keyFlags, keySizes
                        );
                    }
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.KeyAgreement) != KeyUsage.None)
                    { 
                        // выполнить тест
                        TestAgreementGOSTR3410(trustFactory, null, keyPair, keyFlags,  
                            ASN1.GOST.OID.gostR3410_1994_SSDH, keySizes, wrapFlags
                        );
                        // выполнить тест
                        TestAgreementGOSTR3410(trustFactory, null, keyPair, keyFlags,  
                            ASN1.GOST.OID.gostR3410_1994_ESDH, keySizes, wrapFlags
                        );
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
        public static void TestGOSTR3410_2001(CAPI.Factory factory, Container container)
        {
            WriteLine("GOSTR3410.2001");
        
            // указать идентификатор ключа и параметров хэширования
            string keyOID = ASN1.GOST.OID.gostR3410_2001; string hashOID = ASN1.GOST.OID.hashes_test; 
        
            // закодировать параметры алгоритма подписи
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(keyOID), ASN1.Null.Instance
            );
            if (container != null)
            {
                // получить алгоритм выработки подписи
                using (SignHash signHash = container.Provider.CreateAlgorithm<SignHash>(
                    container.Store, parameters))
                try {
                    // выполнить тест
                    Sign.GOSTR3410.ECSignHash.Test256(
                        factory, container, signHash, keyOID, hashOID
                    );
                }
                // удалить ключи из контейнера
                finally { container.DeleteKeys(); }
            
                // вывести сообщение
                Write("OK  "); 
        
                // получить алгоритм проверки подписи
                using (VerifyHash verifyHash = container.Provider.CreateAlgorithm<VerifyHash>(
                    container.Store, parameters))
                {
                    // выполнить тест
                    Sign.GOSTR3410.ECVerifyHash.Test256(verifyHash, keyOID, hashOID);
                }
                // вывести сообщение
                Write("OK  "); 
            }
            else {
                // получить алгоритм выработки подписи
                using (SignHash signHash = factory.CreateAlgorithm<SignHash>(null, parameters))
                {
                    // выполнить тест
                    Sign.GOSTR3410.ECSignHash.Test256(
                        factory, container, signHash, keyOID, hashOID
                    );
                }
                // вывести сообщение
                Write("OK  "); 
            
                // получить алгоритм проверки подписи
                using (VerifyHash verifyHash = factory.CreateAlgorithm<VerifyHash>(null, parameters))
                {
                    // выполнить тест
                    Sign.GOSTR3410.ECVerifyHash.Test256(verifyHash, keyOID, hashOID);
                }
                // вывести сообщение
                Write("OK  "); 
            }
            WriteLine();
        }
        public static void TestGOSTR3410_2001(CAPI.Factory factory, SecurityObject scope, 
            IRand rand, bool generate, KeyFlags keyFlags, string paramOID, 
            string hashOID, string sboxOID, int wrapFlags)
        {
            // сформировать заголовок
            string header = String.Format("{0}/{1}", paramOID, hashOID); 
        
            // сформировать заголовок
            if (sboxOID != null) header = String.Format("{0}/{1}", header, sboxOID); 
        
            // вывести заголовок
            WriteLine("GOSTR3410.2001/{0}", header); 
            
            // указать идентификатор ключа
            string keyOID = ASN1.GOST.OID.gostR3410_2001; int[] keySizes = new int[] {32};
        
            // указать доверенную фабрику
            using (CAPI.Factory trustFactory = new GOST.Factory()) 
            {
                // получить фабрику кодирования ключа
                KeyFactory keyFactory = trustFactory.GetKeyFactory(keyOID); 

                // указать способ использования ключа
                KeyUsage keyUsage = keyFactory.GetKeyUsage(); 

                // скорректировать способ использования ключа
                if (wrapFlags == 0) keyUsage = keyUsage & ~(KeyUsage.KeyEncipherment | KeyUsage.KeyAgreement);
                else { 
                    // скорректировать способ использования ключа
                    keyUsage = keyUsage & ~KeyUsage.DigitalSignature; 
                }
                // в зависимости от параметров
                ASN1.ObjectIdentifier encodedSBoxOID = null; if (sboxOID != null) 
                {
                    // закодировать таблицу подстановок
                    encodedSBoxOID = new ASN1.ObjectIdentifier(sboxOID); 
                }
                // закодировать параметры ключа
                ASN1.IEncodable encodedParameters = new ASN1.GOST.GOSTR3410PublicKeyParameters2001(
                    new ASN1.ObjectIdentifier(paramOID), 
                    new ASN1.ObjectIdentifier(hashOID), encodedSBoxOID
                ); 
                // раскодировать параметры алгоритма
                IParameters parameters = keyFactory.DecodeParameters(encodedParameters); 

                // сгенерировать ключевую пару
                using (KeyPair keyPair = GenerateKeyPair(
                    factory, scope, rand, trustFactory, null, generate, 
                    keyOID, parameters, keyUsage, keyFlags)) 
                try {
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.DigitalSignature) != KeyUsage.None)
                    { 
                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_94), 
                            new ASN1.ObjectIdentifier(hashOID) 
                        ); 
                        // выполнить тест круговой подписи
                        Sign.GOSTR3410.ECSignHash.CircleTest(
                            trustFactory, keyOID, parameters, hashParameters
                        ); 
                        // указать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(keyOID), ASN1.Null.Instance
                        ); 
                        // указать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier signParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_94_R3410_2001), null
                        ); 
                        // выполнить тест
                        SignTest(trustFactory, null, hashParameters, 
                            signHashParameters, signParameters, keyPair, keyFlags 
                        );
                    }
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.KeyEncipherment) != KeyUsage.None)
                    { 
                        // указать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier transportParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(keyOID), ASN1.Null.Instance
                        ); 
                        // выполнить тест
                        TransportKeyTest(trustFactory, null, 
                            transportParameters, keyPair, keyFlags, keySizes
                        );
                    }
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.KeyAgreement) != KeyUsage.None)
                    { 
                        // выполнить тест
                        TestAgreementGOSTR3410(trustFactory, null, keyPair, keyFlags, 
                            ASN1.GOST.OID.gostR3410_2001_SSDH, keySizes, wrapFlags
                        );
                        // выполнить тест
                        TestAgreementGOSTR3410(trustFactory, null, keyPair, keyFlags,  
                            ASN1.GOST.OID.gostR3410_2001_ESDH, keySizes, wrapFlags
                        );
                    }
                }
                // удалить ключи контейнера
                finally { DeleteKeys(scope); }
            }
            WriteLine();
        }
        ////////////////////////////////////////////////////////////////////////////
        // ГОСТ P 34.10-2012-256
        ////////////////////////////////////////////////////////////////////////////
        public static void TestGOSTR3410_2012_256(CAPI.Factory factory, Container container)
        {
            WriteLine("GOSTR3410.2012.256");
        
            // указать идентификатор ключа и алгоритма хэширования
            string keyOID = ASN1.GOST.OID.gostR3410_2012_256; string hashOID = ASN1.GOST.OID.gostR3411_2012_256; 
        
            // закодировать параметры алгоритма подписи
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(keyOID), ASN1.Null.Instance
            );
            if (container != null)
            {
                // получить алгоритм выработки подписи
                using (SignHash signHash = container.Provider.CreateAlgorithm<SignHash>(
                    container.Store, parameters))
                try {
                    // выполнить тест
                    Sign.GOSTR3410.ECSignHash.Test256(
                        factory, container, signHash, keyOID, hashOID
                    );
                }
                // удалить ключи из контейнера
                finally { container.DeleteKeys(); }
            
                // вывести сообщение
                Write("OK  "); 
        
                // получить алгоритм проверки подписи
                using (VerifyHash verifyHash = container.Provider.CreateAlgorithm<VerifyHash>(
                    container.Store, parameters))
                {
                    // выполнить тест
                    Sign.GOSTR3410.ECVerifyHash.Test256(verifyHash, keyOID, hashOID);
                }
                // вывести сообщение
                Write("OK  "); 
            }
            else {
                // получить алгоритм выработки подписи
                using (SignHash signHash = factory.CreateAlgorithm<SignHash>(null, parameters))
                {
                    // выполнить тест
                    Sign.GOSTR3410.ECSignHash.Test256(
                        factory, container, signHash, keyOID, hashOID
                    );
                }
                // вывести сообщение
                Write("OK  "); 
            
                // получить алгоритм проверки подписи
                using (VerifyHash verifyHash = factory.CreateAlgorithm<VerifyHash>(null, parameters))
                {
                    // выполнить тест
                    Sign.GOSTR3410.ECVerifyHash.Test256(verifyHash, keyOID, hashOID);
                }
                // вывести сообщение
                Write("OK  "); 
            }
            WriteLine();
        }
        public static void TestGOSTR3410_2012_256(
            CAPI.Factory factory, SecurityObject scope, IRand rand, bool generate, 
            KeyFlags keyFlags, string paramOID, int[] keySizes, int wrapFlags) 
        {
            // сформировать заголовок
            string header = String.Format("{0}", paramOID); 
        
            // вывести заголовок
            WriteLine("GOSTR3410.2012_256/{0}", header);
        
            // указать идентификатор ключа
            string keyOID = ASN1.GOST.OID.gostR3410_2012_256; 
        
            // указать идентификатор алгоритма хэширования
            string hashOID = ASN1.GOST.OID.gostR3411_2012_256; 

            // указать доверенную фабрику
            using (CAPI.Factory trustFactory = new GOST.Factory()) 
            {
                // получить фабрику кодирования ключа
                KeyFactory keyFactory = trustFactory.GetKeyFactory(keyOID); 

                // указать способ использования ключа
                KeyUsage keyUsage = keyFactory.GetKeyUsage(); 
        
                // скорректировать способ использования ключа
                if (wrapFlags == 0) keyUsage = keyUsage & ~(KeyUsage.KeyEncipherment | KeyUsage.KeyAgreement); 
                else { 
                    // в зависимости от идентификатора
                    if (paramOID != ASN1.GOST.OID.ecc_tc26_2012_256A)
                    { 
                        // скорректировать способ использования ключа
                        keyUsage = keyUsage & ~KeyUsage.DigitalSignature; 
                    }
                }
                // закодировать параметры ключа
                ASN1.IEncodable encodedParameters = new ASN1.GOST.GOSTR3410PublicKeyParameters2012(
                    new ASN1.ObjectIdentifier(paramOID), 
                    new ASN1.ObjectIdentifier(hashOID)
                ); 
                // раскодировать параметры алгоритма
                IParameters parameters = keyFactory.DecodeParameters(encodedParameters); 

                // сгенерировать ключевую пару
                using (KeyPair keyPair = GenerateKeyPair(
                    factory, scope, rand, trustFactory, null, generate, 
                    keyOID, parameters, keyUsage, keyFlags)) 
                try {
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.DigitalSignature) != KeyUsage.None)
                    { 
                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(hashOID), ASN1.Null.Instance
                        ); 
                        // выполнить тест круговой подписи
                        Sign.GOSTR3410.ECSignHash.CircleTest(
                            trustFactory, keyOID, parameters, hashParameters
                        ); 
                        // указать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(keyOID), ASN1.Null.Instance
                        ); 
                        // указать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier signParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_R3410_2012_256), null
                        ); 
                        // выполнить тест
                        SignTest(trustFactory, null, hashParameters, 
                            signHashParameters, signParameters, keyPair, keyFlags 
                        );
                    }
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.KeyEncipherment) != KeyUsage.None)
                    { 
                        // указать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier transportParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(keyOID), ASN1.Null.Instance
                        ); 
                        // для всех размеров
                        foreach (int keySize in keySizes)
                        { 
                            // выполнить тест
                            TransportKeyTest(trustFactory, null, 
                                transportParameters, keyPair, keyFlags, keySize
                            );
                        }
                    }
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.KeyAgreement) != KeyUsage.None)
                    { 
                        // выполнить тесты
                        TestAgreementGOSTR3410(trustFactory, null, keyPair, keyFlags,  
                            ASN1.GOST.OID.gostR3410_2012_DH_256, keySizes, wrapFlags
                        ); 
                    }
                }
                // удалить ключи контейнера
                finally { DeleteKeys(scope); }
            }
            WriteLine();
        }
        ////////////////////////////////////////////////////////////////////////////
        // ГОСТ P 34.10-2012-512
        ////////////////////////////////////////////////////////////////////////////
        public static void TestGOSTR3410_2012_512(
            CAPI.Factory factory, Container container, int[] keySizes)
        {
            Console.WriteLine("GOSTR3410.2012.512");
        
            // закодировать параметры алгоритма подписи
            ASN1.ISO.AlgorithmIdentifier signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2012_512), ASN1.Null.Instance
            );
            // закодировать параметры алгоритма согласования
            ASN1.ISO.AlgorithmIdentifier agreementParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2012_DH_512), ASN1.Null.Instance
            );
            if (container != null)
            {
                // получить алгоритм выработки подписи
                using (SignHash signHash = container.Provider.CreateAlgorithm<SignHash>(
                    container.Store, signParameters))
                try {
                    // выполнить тест
                    Sign.GOSTR3410.ECSignHash.Test512(factory, container, signHash);
                }
                // удалить ключи из контейнера
                finally { container.DeleteKeys(); }

                // вывести сообщение
                Write("OK  "); 
        
                // получить алгоритм проверки подписи
                using (VerifyHash verifyHash = container.Provider.CreateAlgorithm<VerifyHash>(
                    container.Store, signParameters))
                {
                    // выполнить тест
                    Sign.GOSTR3410.ECVerifyHash.Test512(verifyHash);
                }
                // вывести сообщение
                Write("OK  "); 
            
                // получить алгоритм согласования ключа
                using (IKeyAgreement agreement = 
                    container.Provider.CreateAlgorithm<IKeyAgreement>(
                        container.Store, agreementParameters))
                try {
                    // выполнить тест
                    Keyx.GOSTR3410.ECKeyAgreement2012.Test(
                        factory, container, agreement, keySizes
                    );
                }
                // удалить ключи из контейнера
                finally { container.DeleteKeys(); }

                // вывести сообщение
                Write("OK  "); 
            }
            else {
                // получить алгоритм выработки подписи
                using (SignHash signHash = 
                    factory.CreateAlgorithm<SignHash>(null, signParameters))
                {
                    // выполнить тест
                    Sign.GOSTR3410.ECSignHash.Test512(factory, container, signHash);
                }
                // вывести сообщение
                Write("OK  "); 
            
                // получить алгоритм проверки подписи
                using (VerifyHash verifyHash = 
                    factory.CreateAlgorithm<VerifyHash>(null, signParameters))
                {
                    // выполнить тест
                    Sign.GOSTR3410.ECVerifyHash.Test512(verifyHash);
                }
                // вывести сообщение
                Write("OK  "); 

                // получить алгоритм согласования ключа
                using (IKeyAgreement agreement = 
                    factory.CreateAlgorithm<IKeyAgreement>(
                        null, agreementParameters))
                {
                    // выполнить тест
                    Keyx.GOSTR3410.ECKeyAgreement2012.Test(
                        factory, container, agreement, keySizes
                    );
                }
                // вывести сообщение
                Write("OK  "); 
            }
            WriteLine();
        }
        public static void TestGOSTR3410_2012_512(
            CAPI.Factory factory, SecurityObject scope, IRand rand, bool generate, 
            KeyFlags keyFlags, string paramOID, int[] keySizes, int wrapFlags) 
        {
            // сформировать заголовок
            string header = String.Format("{0}", paramOID); 
        
            // вывести заголовок
            WriteLine("GOSTR3410.2012_512/{0}", header);
        
            // указать идентификатор ключа
            string keyOID = ASN1.GOST.OID.gostR3410_2012_512; 
            
            // указать идентификатор алгоритма хэширования
            string hashOID = ASN1.GOST.OID.gostR3411_2012_512; 
        
            // указать доверенную фабрику
            using (CAPI.Factory trustFactory = new GOST.Factory()) 
            {
                // получить фабрику кодирования ключа
                KeyFactory keyFactory = trustFactory.GetKeyFactory(keyOID); 

                // указать способ использования ключа
                KeyUsage keyUsage = keyFactory.GetKeyUsage(); 
        
                // скорректировать способ использования ключа
                if (wrapFlags == 0) keyUsage = keyUsage & ~(KeyUsage.KeyEncipherment | KeyUsage.KeyAgreement);
                    
                // закодировать параметры ключа
                ASN1.IEncodable encodedParameters = new ASN1.GOST.GOSTR3410PublicKeyParameters2012(
                    new ASN1.ObjectIdentifier(paramOID), 
                    new ASN1.ObjectIdentifier(hashOID)
                ); 
                // раскодировать параметры алгоритма
                IParameters parameters = keyFactory.DecodeParameters(encodedParameters); 

                // сгенерировать ключевую пару
                using (KeyPair keyPair = GenerateKeyPair(
                    factory, scope, rand, trustFactory, null, generate, 
                    keyOID, parameters, keyUsage, keyFlags)) 
                try {
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.DigitalSignature) != KeyUsage.None)
                    { 
                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(hashOID), ASN1.Null.Instance
                        ); 
                        // выполнить тест круговой подписи
                        Sign.GOSTR3410.ECSignHash.CircleTest(
                            trustFactory, keyOID, parameters, hashParameters
                        ); 
                        // указать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(keyOID), ASN1.Null.Instance
                        ); 
                        // указать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier signParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_R3410_2012_512), null
                        ); 
                        // выполнить тест
                        SignTest(trustFactory, null, hashParameters, 
                            signHashParameters, signParameters, keyPair, keyFlags 
                        );
                    }
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.KeyEncipherment) != KeyUsage.None)
                    { 
                        // указать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier transportParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(keyOID), ASN1.Null.Instance
                        ); 
                        // для всех размеров
                        foreach (int keySize in keySizes)
                        { 
                            // выполнить тест
                            TransportKeyTest(trustFactory, null, 
                                transportParameters, keyPair, keyFlags, keySize
                            );
                        }
                    }
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.KeyAgreement) != KeyUsage.None)
                    { 
                        // выполнить тест
                        TestAgreementGOSTR3410(trustFactory, null, keyPair, keyFlags,  
                            ASN1.GOST.OID.gostR3410_2012_DH_256, keySizes, wrapFlags
                        ); 
                    }
                }
                // удалить ключи контейнера
                finally { DeleteKeys(scope); }
            }
            WriteLine();
        }
        ////////////////////////////////////////////////////////////////////////////
        // Обмен ключами ГОСТ P 34.10
        ////////////////////////////////////////////////////////////////////////////
        public static void TestAgreementGOSTR3410(CAPI.Factory factory, SecurityStore scope, 
            KeyPair keyPair, KeyFlags keyFlags, string agreementOID, int[] keySizes, int wrapFlags)
        {
            if ((wrapFlags & Wrap.RFC4357.NoneSBoxA) != 0)
            {
                // сгенерировать случайные данные
                byte[] ukm = new byte[8]; Generate(ukm, 0, ukm.Length); 

                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier keyAgreementParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(keyPair.PublicKey.KeyOID), ASN1.Null.Instance
                ); 
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_none), 
                    new ASN1.GOST.KeyWrapParameters(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_A), new ASN1.OctetString(ukm)
                    )
                ); 
                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier esdhParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(agreementOID), wrapParameters
                ); 
                // выполнить тест
                TestAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                    keyAgreementParameters, esdhParameters, keySizes 
                ); 
            }
            if ((wrapFlags & Wrap.RFC4357.NoneSBoxB) != 0)
            {
                // сгенерировать случайные данные
                byte[] ukm = new byte[8]; Generate(ukm, 0, ukm.Length); 

                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier keyAgreementParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(keyPair.PublicKey.KeyOID), ASN1.Null.Instance
                ); 
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_none), 
                    new ASN1.GOST.KeyWrapParameters(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_B), new ASN1.OctetString(ukm)
                    )
                ); 
                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier esdhParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(agreementOID), wrapParameters
                ); 
                // выполнить тест
                TestAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                    keyAgreementParameters, esdhParameters, keySizes 
                ); 
            }
            if ((wrapFlags & Wrap.RFC4357.NoneSBoxC) != 0)
            {
                // сгенерировать случайные данные
                byte[] ukm = new byte[8]; Generate(ukm, 0, ukm.Length); 

                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier keyAgreementParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(keyPair.PublicKey.KeyOID), ASN1.Null.Instance
                ); 
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_none), 
                    new ASN1.GOST.KeyWrapParameters(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_C), new ASN1.OctetString(ukm)
                    )
                ); 
                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier esdhParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(agreementOID), wrapParameters
                ); 
                // выполнить тест
                TestAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                    keyAgreementParameters, esdhParameters, keySizes 
                ); 
            }
            if ((wrapFlags & Wrap.RFC4357.NoneSBoxD) != 0)
            {
                // сгенерировать случайные данные
                byte[] ukm = new byte[8]; Generate(ukm, 0, ukm.Length); 

                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier keyAgreementParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(keyPair.PublicKey.KeyOID), ASN1.Null.Instance
                ); 
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_none), 
                    new ASN1.GOST.KeyWrapParameters(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_D), new ASN1.OctetString(ukm)
                    )
                ); 
                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier esdhParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(agreementOID), wrapParameters
                ); 
                // выполнить тест
                TestAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                    keyAgreementParameters, esdhParameters, keySizes 
                ); 
            }
            if ((wrapFlags & Wrap.RFC4357.NoneSBoxZ) != 0)
            {
                // сгенерировать случайные данные
                byte[] ukm = new byte[8]; Generate(ukm, 0, ukm.Length); 

                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier keyAgreementParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(keyPair.PublicKey.KeyOID), ASN1.Null.Instance
                ); 
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_none), 
                    new ASN1.GOST.KeyWrapParameters(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_tc26_z), new ASN1.OctetString(ukm)
                    )
                ); 
                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier esdhParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(agreementOID), wrapParameters
                ); 
                // выполнить тест
                TestAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                    keyAgreementParameters, esdhParameters, keySizes 
                ); 
            }
            if ((wrapFlags & Wrap.RFC4357.CProSBoxA) != 0)
            {
                // сгенерировать случайные данные
                byte[] ukm = new byte[8]; Generate(ukm, 0, ukm.Length); 

                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier keyAgreementParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(keyPair.PublicKey.KeyOID), ASN1.Null.Instance
                ); 
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_cryptopro), 
                    new ASN1.GOST.KeyWrapParameters(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_A), new ASN1.OctetString(ukm)
                    )
                ); 
                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier esdhParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(agreementOID), wrapParameters
                ); 
                // выполнить тест
                TestAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                    keyAgreementParameters, esdhParameters, keySizes 
                ); 
            }
            if ((wrapFlags & Wrap.RFC4357.CProSBoxB) != 0)
            {
                // сгенерировать случайные данные
                byte[] ukm = new byte[8]; Generate(ukm, 0, ukm.Length); 

                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier keyAgreementParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(keyPair.PublicKey.KeyOID), ASN1.Null.Instance
                ); 
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_cryptopro), 
                    new ASN1.GOST.KeyWrapParameters(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_B), new ASN1.OctetString(ukm)
                    )
                ); 
                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier esdhParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(agreementOID), wrapParameters
                ); 
                // выполнить тест
                TestAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                    keyAgreementParameters, esdhParameters, keySizes 
                ); 
            }
            if ((wrapFlags & Wrap.RFC4357.CProSBoxC) != 0)
            {
                // сгенерировать случайные данные
                byte[] ukm = new byte[8]; Generate(ukm, 0, ukm.Length); 

                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier keyAgreementParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(keyPair.PublicKey.KeyOID), ASN1.Null.Instance
                ); 
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_cryptopro), 
                    new ASN1.GOST.KeyWrapParameters(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_C), new ASN1.OctetString(ukm)
                    )
                ); 
                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier esdhParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(agreementOID), wrapParameters
                ); 
                // выполнить тест
                TestAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                    keyAgreementParameters, esdhParameters, keySizes 
                ); 
            }
            if ((wrapFlags & Wrap.RFC4357.CProSBoxD) != 0)
            {
                // сгенерировать случайные данные
                byte[] ukm = new byte[8]; Generate(ukm, 0, ukm.Length); 

                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier keyAgreementParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(keyPair.PublicKey.KeyOID), ASN1.Null.Instance
                ); 
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_cryptopro), 
                    new ASN1.GOST.KeyWrapParameters(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_D), new ASN1.OctetString(ukm)
                    )
                ); 
                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier esdhParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(agreementOID), wrapParameters
                ); 
                // выполнить тест
                TestAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                    keyAgreementParameters, esdhParameters, keySizes 
                ); 
            }
            if ((wrapFlags & Wrap.RFC4357.CProSBoxZ) != 0)
            {
                // сгенерировать случайные данные
                byte[] ukm = new byte[8]; Generate(ukm, 0, ukm.Length); 

                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier keyAgreementParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(keyPair.PublicKey.KeyOID), ASN1.Null.Instance
                ); 
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_cryptopro), 
                    new ASN1.GOST.KeyWrapParameters(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_tc26_z), new ASN1.OctetString(ukm)
                    )
                ); 
                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier esdhParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(agreementOID), wrapParameters
                ); 
                // выполнить тест
                TestAgreementGOSTR3410(factory, scope, keyPair, keyFlags, 
                    keyAgreementParameters, esdhParameters, keySizes 
                ); 
            }
        }
        public static void TestAgreementGOSTR3410(CAPI.Factory factory, SecurityStore scope, 
            KeyPair keyPair, KeyFlags keyFlags, ASN1.ISO.AlgorithmIdentifier keyAgreementParameters, 
            ASN1.ISO.AlgorithmIdentifier esdhParameters, int[] keySizes)
        {
            // указать способ использования ключа
            KeyUsage keyUsage = KeyUsage.KeyAgreement; 
        
            // указать генератор случайных данных
            using (IRand rand = new CAPI.Rand(null))
            {
                // сгенерировать ключевую пару
                using (KeyPair ephemeralKeyPair = factory.GenerateKeyPair(
                    scope, rand, null, keyPair.PublicKey.KeyOID, 
                    keyPair.PublicKey.Parameters, keyUsage, KeyFlags.None)) 
                {
                    if (keyAgreementParameters != null) 
                    {
                        // для всех размеров
                        foreach (int keySize in keySizes)
                        { 
                            // выполнить тест
                            KeyAgreementTest(factory, scope, keyAgreementParameters, 
                                keyPair, keyFlags, ephemeralKeyPair, keySize
                            );
                        }
                    }
                    if (esdhParameters != null) 
                    {
                        // для всех размеров
                        foreach (int keySize in keySizes)
                        { 
                            // выполнить тест
                            TransportAgreementTest(factory, scope, esdhParameters, 
                                keyPair, keyFlags, ephemeralKeyPair, keySize
                            );
                        }
                    }
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // ГОСТ CMS
        ///////////////////////////////////////////////////////////////////////
        public class CMS : RefObject
        {
            // личный ключ и сертификатт открытого ключа
            private IPrivateKey privateKey; private Certificate certificate;
            // сертификат открытого ключа другой стороны
            private Certificate otherCertificate;
    
            // конструктор
            public CMS(CAPI.Factory factory, string certificateBase64, 
                byte[] encodedPrivateKey, string otherCertificateBase64, string caCertificateBase64) 
            {
                // открытый ключ и параметры ключа
                GOSTR3410.ECPublicKey   publicKey  = null; 
                GOSTR3410.IECParameters parameters = null; 

                Certificate certificateCA = null; if (caCertificateBase64 != null) 
                {
                    // получить закодированный сертификат
                    byte[] encodedCertificate = Base64.GetDecoder().Decode(caCertificateBase64);

                    // раскодировать сертификат
                    certificateCA = new Certificate(encodedCertificate); 
                }
                if (otherCertificateBase64 == null) otherCertificate = null; 
                else {
                    // получить закодированный сертификат
                    byte[] encodedCertificate = Base64.GetDecoder().Decode(otherCertificateBase64);

                    // раскодировать сертификат
                    otherCertificate = new Certificate(encodedCertificate); 

                    // проверить подпись сертификата
                    if (certificateCA != null) PKI.VerifyCertificate(
                        factory, null, otherCertificate, certificateCA
                    );
                    // извлечь открытый ключ
                    publicKey = (GOSTR3410.ECPublicKey)otherCertificate.GetPublicKey(factory); 

                    // указать параметры ключа
                    parameters = (GOSTR3410.IECParameters)publicKey.Parameters; 

                    // проверить принадлежность точки кривой
                    if (!parameters.Curve.IsPoint(publicKey.Q)) throw new ArgumentException();
                }
                if (certificateBase64 == null) certificate = null; 
                else {
                    // получить закодированный сертификат
                    byte[] encodedCertificate = Base64.GetDecoder().Decode(certificateBase64);

                    // раскодировать сертификат
                    certificate = new Certificate(encodedCertificate); 

                    // проверить подпись сертификата
                    if (certificateCA != null) PKI.VerifyCertificate(
                        factory, null, certificate, certificateCA
                    );
                    // извлечь открытый ключ
                    publicKey = (GOSTR3410.ECPublicKey)certificate.GetPublicKey(factory); 

                    // указать параметры ключа
                    parameters = (GOSTR3410.IECParameters)publicKey.Parameters; 

                    // проверить принадлежность точки кривой
                    if (!parameters.Curve.IsPoint(publicKey.Q)) throw new ArgumentException();
                }
                // указать личный ключ
                privateKey = new GOST.GOSTR3410.ECPrivateKey(
                    factory, null, publicKey.KeyOID, parameters, 
                    Math.Convert.ToBigInteger(encodedPrivateKey, Math.Endian.BigEndian)
                ); 
                // извлечь значение личного ключа
                Math.BigInteger x = ((GOSTR3410.ECPrivateKey)privateKey).D; 
                
                // выполнить математические операции
                EC.Point check = parameters.Curve.Multiply(parameters.Generator, x);
            
                // сравнить соответствие личного и открытого ключа
                if (!check.Equals(publicKey.Q)) throw new ArgumentException(); 
            }
            // освободить выделенные ресурсы
            protected override void OnDispose()
            {
                // освободить выделенные ресурсы
                privateKey.Dispose(); base.OnDispose();
            }
            // проверить подписанное сообщение
            public byte[] TestSignedMessage(string messageBase64) 
            {
                // получить закодированную структуру
                ASN1.ISO.PKCS.ContentInfo contentInfo = new ASN1.ISO.PKCS.ContentInfo(
                    ASN1.Encodable.Decode(Base64.GetDecoder().Decode(messageBase64))
                );
                // извлечь внутренние данные
                ASN1.ISO.PKCS.PKCS7.SignedData signedData = 
                    new ASN1.ISO.PKCS.PKCS7.SignedData(contentInfo.Inner); 

                // проверить подпись данных
                CAPI.CMS.VerifySign(privateKey.Factory, privateKey.Scope, otherCertificate, signedData); 
        
                // вернуть подписанные данные
                return signedData.EncapContentInfo.EContent.Value; 
            }
            public byte[] TestEnvelopedMessage(String messageBase64)
            {
                // получить закодированную структуру
                ASN1.ISO.PKCS.ContentInfo contentInfo = new ASN1.ISO.PKCS.ContentInfo(
                    ASN1.Encodable.Decode(Base64.GetDecoder().Decode(messageBase64))
                );
                // извлечь внутренние данные
                ASN1.ISO.PKCS.PKCS7.EnvelopedData envelopedData = 
                    new ASN1.ISO.PKCS.PKCS7.EnvelopedData(contentInfo.Inner); 
        
                // расшифровать данные
                return CAPI.CMS.KeyxDecryptData(privateKey, 
                    certificate, otherCertificate, envelopedData).Content; 
            }
            public static void Test(CAPI.Factory factory)
            {
                // указать используемую кодировку
                Encoding encoding = Encoding.GetEncoding(1251); 

                string certificateCA = null; 
                using (CMS pki2001 = new CMS(factory, null,  
                    new byte[] {
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
                )){ 
                    string msg2001_1 = encoding.GetString(pki2001.TestSignedMessage( 
                        "MIIBKAYJKoZIhvcNAQcCoIIBGTCCARUCAQExDDAKBgYqhQMCAgkFADAbBgkqhkiG" + 
                        "9w0BBwGgDgQMc2FtcGxlIHRleHQKMYHkMIHhAgEBMIGBMG0xHzAdBgNVBAMMFkdv" + 
                        "c3RSMzQxMC0yMDAxIGV4YW1wbGUxEjAQBgNVBAoMCUNyeXB0b1BybzELMAkGA1UE" + 
                        "BhMCUlUxKTAnBgkqhkiG9w0BCQEWGkdvc3RSMzQxMC0yMDAxQGV4YW1wbGUuY29t" + 
                        "AhAr9cYewhG9F8fc1GJmtC4hMAoGBiqFAwICCQUAMAoGBiqFAwICEwUABEDAw0LZ" + 
                        "P4/+JRERiHe/icPbg0IE1iD5aCqZ9v4wO+T0yPjVtNr74caRZzQfvKZ6DRJ7/RAl" + 
                        "xlHbjbL0jHF+7XKp"
                    ));
                    string msg2001_2 = encoding.GetString(pki2001.TestEnvelopedMessage( 
                        "MIIBpAYJKoZIhvcNAQcDoIIBlTCCAZECAQIxggFQoYIBTAIBA6BloWMwHAYGKoUD" + 
                        "AgITMBIGByqFAwICJAAGByqFAwICHgEDQwAEQLNVOfRngZcrpcTZhB8n+4HtCDLm" + 
                        "mtTyAHi4/4Nk6tIdsHg8ff4DwfQG5DvMFrnF9vYZNxwXuKCqx9GhlLOlNiChCgQI" + 
                        "L/D20YZLMoowHgYGKoUDAgJgMBQGByqFAwICDQAwCQYHKoUDAgIfATCBszCBsDCB" + 
                        "gTBtMR8wHQYDVQQDDBZHb3N0UjM0MTAtMjAwMSBleGFtcGxlMRIwEAYDVQQKDAlD" + 
                        "cnlwdG9Qcm8xCzAJBgNVBAYTAlJVMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAt" + 
                        "MjAwMUBleGFtcGxlLmNvbQIQK/XGHsIRvRfH3NRiZrQuIQQqMCgEIBajHOfOTukN" + 
                        "8ex0aQRoHsefOu24Ox8dSn75pdnLGdXoBAST/YZ+MDgGCSqGSIb3DQEHATAdBgYq" + 
                        "hQMCAhUwEwQItzXhegc1oh0GByqFAwICHwGADDmxivS/qeJlJbZVyQ=="
                    ));
                    string msg2001_3 = encoding.GetString(pki2001.TestEnvelopedMessage( 
                        "MIIBpwYJKoZIhvcNAQcDoIIBmDCCAZQCAQAxggFTMIIBTwIBADCBgTBtMR8wHQYD" + 
                        "VQQDDBZHb3N0UjM0MTAtMjAwMSBleGFtcGxlMRIwEAYDVQQKDAlDcnlwdG9Qcm8x" + 
                        "CzAJBgNVBAYTAlJVMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAwMUBleGFt" + 
                        "cGxlLmNvbQIQK/XGHsIRvRfH3NRiZrQuITAcBgYqhQMCAhMwEgYHKoUDAgIkAAYH" + 
                        "KoUDAgIeAQSBpzCBpDAoBCBqL6ghBpVon5/kR6qey2EVK35BYLxdjfv1PSgbGJr5" + 
                        "dQQENm2Yt6B4BgcqhQMCAh8BoGMwHAYGKoUDAgITMBIGByqFAwICJAAGByqFAwIC" + 
                        "HgEDQwAEQE0rLzOQ5tyj3VUqzd/g7/sx93N+Tv+/eImKK8PNMZQESw5gSJYf28dd" + 
                        "Em/askCKd7W96vLsNMsjn5uL3Z4SwPYECJeV4ywrrSsMMDgGCSqGSIb3DQEHATAd" + 
                        "BgYqhQMCAhUwEwQIvBCLHwv/NCkGByqFAwICHwGADKqOch3uT7Mu4w+hNw=="
                    )); 
                }
                using (CMS pki2012_256 = new CMS(factory, null, 
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
                )){ 
                    string msg2012_256_1 = encoding.GetString(pki2012_256.TestSignedMessage( 
                        "MIIBBQYJKoZIhvcNAQcCoIH3MIH0AgEBMQ4wDAYIKoUDBwEBAgIFADAbBgkqhkiG" + 
                        "9w0BBwGgDgQMVGVzdCBtZXNzYWdlMYHBMIG+AgEBMFswVjEpMCcGCSqGSIb3DQEJ" + 
                        "ARYaR29zdFIzNDEwLTIwMTJAZXhhbXBsZS5jb20xKTAnBgNVBAMTIEdvc3RSMzQx" + 
                        "MC0yMDEyICgyNTYgYml0KSBleGFtcGxlAgEBMAwGCCqFAwcBAQICBQAwDAYIKoUD" + 
                        "BwEBAQEFAARAkptb2ekZbC94FaGDQeP70ExvTkXtOY9zgz3cCco/hxPhXUVo3eCx" + 
                        "VNwDQ8enFItJZ8DEX4blZ8QtziNCMl5HbA==" 
                    ));
                    string msg2012_256_2 = encoding.GetString(pki2012_256.TestEnvelopedMessage( 
                        "MIIBhgYJKoZIhvcNAQcDoIIBdzCCAXMCAQIxggEwoYIBLAIBA6BooWYwHwYIKoUD" + 
                        "BwEBAQEwEwYHKoUDAgIkAAYIKoUDBwEBAgIDQwAEQPAdWM4pO38iZ49UjaXQpq+a" + 
                        "jhTa4KwY4B9TFMK7AiYmbFKE0eX/wvu69kFMQ2o3OJTnMOlr1WHiPYOmNO6C5hOh" + 
//                      "CgQIX+vNomZakEIwIgYIKoUDBwEBAQEwFgYHKoUDAgINADALBgkqhQMHAQIFAQEw" + 
                        "CgQIX+vNomZakEIwIgYIKoUDBwEBBgEwFgYHKoUDAgINADALBgkqhQMHAQIFAQEw" + // EBBg вместо EBAQ 
                        "gYwwgYkwWzBWMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAxMkBleGFtcGxl" + 
                        "LmNvbTEpMCcGA1UEAxMgR29zdFIzNDEwLTIwMTIgMjU2IGJpdHMgZXhjaGFuZ2UC" + 
                        "AQEEKjAoBCCNhrZOr7x2fsjjQAeDMv/tSoNRQSSQzzxgqdnYxJ3fIAQEgYLqVDA6" + 
                        "BgkqhkiG9w0BBwEwHwYGKoUDAgIVMBUECHVmR/S+hlYiBgkqhQMHAQIFAQGADEI9" + 
                        "UNjyuY+54uVcHw=="
                    ));
                    string msg2012_256_3 = encoding.GetString(pki2012_256.TestEnvelopedMessage( 
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
                    )); 
                }
                using (CMS pki2012_512 = new CMS(factory, null,   
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
                    string msg2012_512_1 = encoding.GetString(pki2012_512.TestSignedMessage( 
                        "MIIBSQYJKoZIhvcNAQcCoIIBOjCCATYCAQExDjAMBggqhQMHAQECAwUAMBsGCSqG" + 
                        "SIb3DQEHAaAOBAxUZXN0IG1lc3NhZ2UxggECMIH/AgEBMFswVjEpMCcGCSqGSIb3" + 
                        "DQEJARYaR29zdFIzNDEwLTIwMTJAZXhhbXBsZS5jb20xKTAnBgNVBAMTIEdvc3RS" + 
                        "MzQxMC0yMDEyICg1MTIgYml0KSBleGFtcGxlAgEBMAwGCCqFAwcBAQIDBQAwDAYI" + 
                        "KoUDBwEBAQIFAASBgFyVohNhMHUi/+RAF3Gh/cC7why6v+4jPWVlx1TYlXtV8Hje" + 
                        "hI2Y+rP52/LO6EUHG/XcwCBbUxmRWsbUSRRBAexmaafkSdvv2FFwC8kHOcti+UPX" + 
                        "PS+KRYxT8vhcsBLWWxDkc1McI7aF09hqtED36mQOfACzeJjEoUjALpmJob1V" 
                    )); 
                    string msg2012_512_2 = encoding.GetString(pki2012_512.TestEnvelopedMessage( 
                        "MIIBzAYJKoZIhvcNAQcDoIIBvTCCAbkCAQIxggF2oYIBcgIBA6CBraGBqjAhBggq" + 
                        "hQMHAQEBAjAVBgkqhQMHAQIBAgIGCCqFAwcBAQIDA4GEAASBgCB0nQy/Ljva/mRj" + 
                        "w6o+eDKIvnxwYIQB5XCHhZhCpHNZiWcFxFpYXZLWRPKifOxV7NStvqGE1+fkfhBe" + 
                        "btkQu0tdC1XL3LO2Cp/jX16XhW/IP5rKV84qWr1Owy/6tnSsNRb+ez6IttwVvaVV" + 
//                      "pA6ONFy9p9gawoC8nitvAVJkWW0PoQoECDVfxzxgMTAHMCIGCCqFAwcBAQECMBYG" + 
                        "pA6ONFy9p9gawoC8nitvAVJkWW0PoQoECDVfxzxgMTAHMCIGCCqFAwcBAQYCMBYG" + // QYCM вместо QECM
                        "ByqFAwICDQAwCwYJKoUDBwECBQEBMIGMMIGJMFswVjEpMCcGCSqGSIb3DQEJARYa" + 
                        "R29zdFIzNDEwLTIwMTJAZXhhbXBsZS5jb20xKTAnBgNVBAMTIEdvc3RSMzQxMC0y" + 
                        "MDEyIDUxMiBiaXRzIGV4Y2hhbmdlAgEBBCowKAQg8C/OcxRR0Uq8nDjHrQlayFb3" + 
                        "WFUZEnEuAKcuG6dTOawEBLhi9hIwOgYJKoZIhvcNAQcBMB8GBiqFAwICFTAVBAiD" + 
                        "1wH+CX6CwgYJKoUDBwECBQEBgAzUvQI4H2zRfgNgdlY="
                    )); 
                    string msg2012_512_3 = encoding.GetString(pki2012_512.TestEnvelopedMessage( 
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
                    )); 
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
                using (CMS pki2012_256 = new CMS(factory, 
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
                    string msg2012_256_1 = encoding.GetString(pki2012_256.TestSignedMessage( 
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
                    )); 
/*                    string msg2012_256_2 = encoding.GetString(pki2012_256.TestEnvelopedMessage( 
                        "MIIBawYJKoZIhvcNAQcDoIIBXDCCAVgCAQIxgfehgfQCAQOgQjBAMDgxDTALBgNV" + 
                        "BAoTBFRLMjYxJzAlBgNVBAMTHkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJp" + 
                        "dAIEAYy6gqEiBCBvcfyuSF57y8vVyaw8Z0ch3wjC4lPKTrpVRXty4Rhk5DAXBgkq" + 
                        "hQMHAQEHAQEwCgYIKoUDBwEBBgEwbjBsMEAwODENMAsGA1UEChMEVEsyNjEnMCUG" + 
                        "A1UEAxMeQ0EgVEsyNjogR09TVCAzNC4xMC0xMiAyNTYtYml0AgQBjLqDBChPbi6B" + 
                        "krXuLPexPAL2oUGCFWDGQHqINL5ExuMBG7/5XQRqriKARVa0MFkGCSqGSIb3DQEH" + 
                        "ATAbBgkqhQMHAQEFAQEwDgQMdNdCKnYAAAAwqTEDgC9O2bYyTGQJ8WUQGq0zHwzX" + 
                        "L0jFhWHTF1tcAxYmd9pX5i89UwIxhtYqyjX1QHju2g=="
                    )); 
                    string msg2012_256_3 = encoding.GetString(pki2012_256.TestEnvelopedMessage( 
                        "MIIBlQYJKoZIhvcNAQcDoIIBhjCCAYICAQAxggEcMIIBGAIBADBAMDgxDTALBgNV" + 
                        "BAoTBFRLMjYxJzAlBgNVBAMTHkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJp" + 
                        "dAIEAYy6gzAXBgkqhQMHAQEHAgEwCgYIKoUDBwEBBgEEgbcwgbQEMFiMredFR3Mv" + 
                        "3g2wqyVXRnrhYEBMNFaqqgBpHwPQh3bF98tt9HZPxRDCww0OPfxeuTBeMBcGCCqF" + 
                        "AwcBAQEBMAsGCSqFAwcBAgEBAQNDAARAdFJ9ww+3ptvQiaQpizCldNYhl4DB1rl8" + 
                        "Fx/2FIgnwssCbYRQ+UuRsTk9dfLLTGJG3JIEXKFxXWBgOrK965A5pAQg9f2/EHxG" + 
                        "DfetwCe1a6uUDCWD+wp5dYOpfkry8YRDEJgwXQYJKoZIhvcNAQcBMB8GCSqFAwcB" + 
                        "AQUCATASBBDUHNxmVclO/v3OaY9P7jxOgC+sD9CHGlEMRUpfGn6yfFDMExmYeby8" + 
                        "LzdPJe1MkYV0qQgdC1zI3nQ7/4taf+4zRA=="
                    )); 
*/                }
                using (CMS pki2012_512 = new CMS(factory, 
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
                    string msg2012_512_1 = encoding.GetString(pki2012_512.TestSignedMessage( 
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
                    )); 
                    string msg2012_512_2 = encoding.GetString(pki2012_512.TestEnvelopedMessage( 
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
                    )); 
                    string msg2012_512_3 = encoding.GetString(pki2012_512.TestEnvelopedMessage( 
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
                    )); 
                }
                certificateCA = 
                    "MIIB+TCCAaagAwIBAgIEAYy6gTAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2" + 
                    "MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEw" +
                    "MTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA4MQ0wCwYDVQQKEwRUSzI2MScwJQYD" +
                    "VQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwXjAXBggqhQMHAQEB" +
                    "ATALBgkqhQMHAQIBAQEDQwAEQBpKgpyPDnhQAJyLqy8Qs0XQhgxEhby6tSypqYim" +
                    "gbjpcKqtU64jpDXc3h3BxGxtl2oHJ/4YLZ/ll87dto3ltMqjgZgwgZUwYwYDVR0j" +
                    "BFwwWoAUrGwOTERmokKW4p8JOyVm88ukUyqhPKQ6MDgxDTALBgNVBAoTBFRLMjYx" +
                    "JzAlBgNVBAMTHkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJpdIIEAYy6gTAd" +
                    "BgNVHQ4EFgQUrGwOTERmokKW4p8JOyVm88ukUyowDwYDVR0TAQH/BAUwAwEB/zAK" +
                    "BggqhQMHAQEDAgNBABGg3nhgQ5oCKbqlEdVaRxH+1WX4wVkawGXuTYkr1AC2OWw3" +
                    "ZC14Vvg3nazm8UMWUZtkvu1kJcHQ4jFKkjUeg2E=";
                using (CMS pki2012_256 = new CMS(factory, 
                    "MIIB6jCCAZegAwIBAgIEAYy6gzAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2" + 
                    "MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEw" + 
                    "MTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA6MQ0wCwYDVQQKEwRUSzI2MSkwJwYD" + 
                    "VQQDEyBSRUNJUElFTlQ6IEdPU1QgMzQuMTAtMTIgMjU2LWJpdDBeMBcGCCqFAwcB" + 
                    "AQEBMAsGCSqFAwcBAgEBAQNDAARAvyeCGXMsYwpYe5aE0w8w3m4vpKQapGInqpnF" + 
                    "lv7h08psFP0s1W80q3BR534F4TmR+o5+iU+AW6ycvWuc73JEQ6OBhzCBhDBjBgNV" + 
                    "HSMEXDBagBSsbA5MRGaiQpbinwk7JWbzy6RTKqE8pDowODENMAsGA1UEChMEVEsy" + 
                    "NjEnMCUGA1UEAxMeQ0EgVEsyNjogR09TVCAzNC4xMC0xMiAyNTYtYml0ggQBjLqB" + 
                    "MB0GA1UdDgQWBBQ35gHPN1bx8l2eEMTbrtIg+5MU0TAKBggqhQMHAQEDAgNBABF2" + 
                    "RHDaRqQuBS2yu7yGIGFgA6c/LG4GKjSOwYsRVmXJNNkQ4TB7PB8j3q7gx2koPsVB" + 
                    "m90WfMWSL6SNSh3muuM=", 
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
                    "MIIB6zCCAZigAwIBAgIEAYy6gjAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2" + 
                    "MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEw" + 
                    "MTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA7MQ0wCwYDVQQKEwRUSzI2MSowKAYD" + 
                    "VQQDEyFPUklHSU5BVE9SOiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwXjAXBggqhQMH" + 
                    "AQEBATALBgkqhQMHAQIBAQEDQwAEQJYpDRNiWWqDgaZje0EmLLOldQ35o5X1ZuZN" + 
                    "SKequYQc/soI3OgDMWD7ThJJCk01IelCeb6MsBmG4lol+pnpVtOjgYcwgYQwYwYD" + 
                    "VR0jBFwwWoAUrGwOTERmokKW4p8JOyVm88ukUyqhPKQ6MDgxDTALBgNVBAoTBFRL" + 
                    "MjYxJzAlBgNVBAMTHkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJpdIIEAYy6" + 
                    "gTAdBgNVHQ4EFgQUPx5RgcjkifhlJm4/jQdkbm30rVQwCgYIKoUDBwEBAwIDQQA6" + 
                    "8x7Vk6PvP/8xOGHhf8PuqaXAYskSyJPuBu+3Bo/PEj10devwc1J9uYWIDCGdKKPy" + 
                    "bSlnQHqUPBBPM30YX1YN", certificateCA
                )) {
                    string msg2012_256_1 = encoding.GetString(pki2012_256.TestSignedMessage( 
                        "MIIC+QYJKoZIhvcNAQcCoIIC6jCCAuYCAQExDDAKBggqhQMHAQECAjA7BgkqhkiG" + 
                        "9w0BBwGgLgQsyu7t8vDu6/zt++kg7/Do7OXwIOTr/yDx8vDz6vLz8PsgU2lnbmVk" + 
                        "RGF0YS6gggHvMIIB6zCCAZigAwIBAgIEAYy6gjAKBggqhQMHAQEDAjA4MQ0wCwYD" + 
                        "VQQKEwRUSzI2MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1i" + 
                        "aXQwHhcNMDEwMTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA7MQ0wCwYDVQQKEwRU" + 
                        "SzI2MSowKAYDVQQDEyFPUklHSU5BVE9SOiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQw" + 
                        "XjAXBggqhQMHAQEBATALBgkqhQMHAQIBAQEDQwAEQJYpDRNiWWqDgaZje0EmLLOl" + 
                        "dQ35o5X1ZuZNSKequYQc/soI3OgDMWD7ThJJCk01IelCeb6MsBmG4lol+pnpVtOj" + 
                        "gYcwgYQwYwYDVR0jBFwwWoAUrGwOTERmokKW4p8JOyVm88ukUyqhPKQ6MDgxDTAL" + 
                        "BgNVBAoTBFRLMjYxJzAlBgNVBAMTHkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2" + 
                        "LWJpdIIEAYy6gTAdBgNVHQ4EFgQUPx5RgcjkifhlJm4/jQdkbm30rVQwCgYIKoUD" + 
                        "BwEBAwIDQQA68x7Vk6PvP/8xOGHhf8PuqaXAYskSyJPuBu+3Bo/PEj10devwc1J9" + 
                        "uYWIDCGdKKPybSlnQHqUPBBPM30YX1YNMYGiMIGfAgEBMEAwODENMAsGA1UEChME" + 
                        "VEsyNjEnMCUGA1UEAxMeQ0EgVEsyNjogR09TVCAzNC4xMC0xMiAyNTYtYml0AgQB" + 
                        "jLqCMAoGCCqFAwcBAQICMAoGCCqFAwcBAQEBBEAVAajM7ZUSj46D6eEG48jGY4BI" + 
                        "MaME8XwiOc2OZeDulzxJc3My8o3M53erK4OUab1i2KYZ66mOLoEC7KsN+FDr"
                    )); 
                    // ОШИБКА
/*                  string msg2012_256_2 = encoding.GetString(pki2012_256.TestEnvelopedMessage( 
                        "MIIDYgYJKoZIhvcNAQcDoIIDUzCCA08CAQKgggHzoIIB7zCCAeswggGYoAMCAQIC" + 
                        "BAGMuoIwCgYIKoUDBwEBAwIwODENMAsGA1UEChMEVEsyNjEnMCUGA1UEAxMeQ0Eg" + 
                        "VEsyNjogR09TVCAzNC4xMC0xMiAyNTYtYml0MB4XDTAxMDEwMTAwMDAwMFoXDTQ5" + 
                        "MTIzMTAwMDAwMFowOzENMAsGA1UEChMEVEsyNjEqMCgGA1UEAxMhT1JJR0lOQVRP" + 
                        "UjogR09TVCAzNC4xMC0xMiAyNTYtYml0MF4wFwYIKoUDBwEBAQEwCwYJKoUDBwEC" + 
                        "AQEBA0MABECWKQ0TYllqg4GmY3tBJiyzpXUN+aOV9WbmTUinqrmEHP7KCNzoAzFg" + 
                        "+04SSQpNNSHpQnm+jLAZhuJaJfqZ6VbTo4GHMIGEMGMGA1UdIwRcMFqAFKxsDkxE" + 
                        "ZqJCluKfCTslZvPLpFMqoTykOjA4MQ0wCwYDVQQKEwRUSzI2MScwJQYDVQQDEx5D" + 
                        "QSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXSCBAGMuoEwHQYDVR0OBBYEFD8e" + 
                        "UYHI5In4ZSZuP40HZG5t9K1UMAoGCCqFAwcBAQMCA0EAOvMe1ZOj7z//MThh4X/D" + 
                        "7qmlwGLJEsiT7gbvtwaPzxI9dHXr8HNSfbmFiAwhnSij8m0pZ0B6lDwQTzN9GF9W" + 
                        "DTGB96GB9AIBA6BCMEAwODENMAsGA1UEChMEVEsyNjEnMCUGA1UEAxMeQ0EgVEsy" + 
                        "NjogR09TVCAzNC4xMC0xMiAyNTYtYml0AgQBjLqCoSIEIMPNyy34te/fxkU5sBsu" + 
                        "PKg0dRileHehwpvlkwtMAXULMBcGCSqFAwcBAQcBATAKBggqhQMHAQEGATBuMGww" + 
                        "QDA4MQ0wCwYDVQQKEwRUSzI2MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEw" + 
                        "LTEyIDI1Ni1iaXQCBAGMuoMEKIvnvZckeH4kcShxLbPHra6YZ4G0dsYHyxqp47J0" + 
                        "9Ue0bLaU4UyZnfswWQYJKoZIhvcNAQcBMBsGCSqFAwcBAQUBATAOBAxHNIgwAAAA" + 
                        "AAAAAACALx+QhUp4gvbGLB3vh+tFGUcGkKaSN3gZce8VURIfpINvLbVDSRrlLqil" + 
                        "y+C8gkYn"
                    )); 
                    // ОШИБКА
                    string msg2012_256_3 = encoding.GetString(pki2012_256.TestEnvelopedMessage( 
                        "MIIBlQYJKoZIhvcNAQcDoIIBhjCCAYICAQAxggEcMIIBGAIBADBAMDgxDTALBgNV" + 
                        "BAoTBFRLMjYxJzAlBgNVBAMTHkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJp" + 
                        "dAIEAYy6gzAXBgkqhQMHAQEHAgEwCgYIKoUDBwEBBgEEgbcwgbQEMFcMddCZTWrx" + 
                        "nX6+KmjqLPXgM/CgzJ3OsipqdynOdnqHSIV4+de++g9/okTohxSczzBeMBcGCCqF" + 
                        "AwcBAQEBMAsGCSqFAwcBAgEBAQNDAARAj4IWWTaXATj140+Gp9mK97BG0/1pUNdo" + 
                        "pMbeq++lMDE3ios/mHf6tTApylo8T1U8gVs2lw+/wYS4KWNaeo3W/gQgI5rnHZO5" + 
                        "ONsVzhw+4+WK6jdIeI5+KRd9o4NasxACfmYwXQYJKoZIhvcNAQcBMB8GCSqFAwcB" + 
                        "AQUCATASBBAWxF6hGJ034AAAAAAAAAAAgC/zjFxalfzn+RnUVhH9Bmc/FYuq3cK6" + 
                        "wUjUSBFCAfVuZOMlVPqnDUKXSwCKOhG/7A=="
                    )); 
*/              }
                using (CMS pki2012_512 = new CMS(factory, 
                    "MIIB5zCCAZSgAwIBAgIEAYy6hTAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2" + 
                    "MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEw" + 
                    "MTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA6MQ0wCwYDVQQKEwRUSzI2MSkwJwYD" + 
                    "VQQDEyBSRUNJUElFTlQ6IEdPU1QgMzQuMTAtMTIgNTEyLWJpdDCBoDAXBggqhQMH" + 
                    "AQEBAjALBgkqhQMHAQIBAgEDgYQABIGApq7AZi9STPPX2DQs/+nN5F2bDLWb5BLL" + 
                    "1blmsv8Aa4mh+bYBGPPjSjM1tbpun2GQe7zHrotfu7nPP5B5Lb5fmibXxReuIKia" + 
                    "A7T6qFltz4fO7R5DwWM53wukuTdPPN8GW18s5fkiI8uN66b6lI/RCOhcBVyuin/8" + 
                    "HjK9ki6S9E6jQjBAMB8GA1UdIwQYMBaAFKxsDkxEZqJCluKfCTslZvPLpFMqMB0G" + 
                    "A1UdDgQWBBSQhVvnfj4gKiX/xFuOOyvGa8VGCDAKBggqhQMHAQEDAgNBAB0z5fBV" + 
                    "z1B04tCbGPc1VeOZitVgBQgxtHmEojXOyBJmJ4vYoJdzEsMKH24Mhhann5Ap9aRb" + 
                    "6YQ1tYdZasw0fus=", 
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
                    "MIICLjCCAdugAwIBAgIEAYy6hDAKBggqhQMHAQEDAjA4MQ0wCwYDVQQKEwRUSzI2" + 
                    "MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXQwHhcNMDEw" + 
                    "MTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA7MQ0wCwYDVQQKEwRUSzI2MSowKAYD" + 
                    "VQQDEyFPUklHSU5BVE9SOiBHT1NUIDM0LjEwLTEyIDUxMi1iaXQwgaAwFwYIKoUD" + 
                    "BwEBAQIwCwYJKoUDBwECAQIBA4GEAASBgLSLt1q8KQ4YZVxioU+1LV9QhE7MHR9g" + 
                    "BEh7S1yVNGlqt7+rNG5VFqmrPM74rbUsOlhV8M+zZKprXdk35Oz8lSW/n2oIUHZx" + 
                    "ikXIH/SSHj4rv3K/Puvz7hYTQSZl/xPdp78nUmjrEa6d5wfX8biEy2z0dgufFvAk" + 
                    "Mw1Ua4gdXqDOo4GHMIGEMGMGA1UdIwRcMFqAFKxsDkxEZqJCluKfCTslZvPLpFMq" + 
                    "oTykOjA4MQ0wCwYDVQQKEwRUSzI2MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0" + 
                    "LjEwLTEyIDI1Ni1iaXSCBAGMuoEwHQYDVR0OBBYEFH4GVwmYDK1rCKhX7nkAWDrJ" + 
                    "16CkMAoGCCqFAwcBAQMCA0EACl6p8dAbpi9Hk+3mgMyI0WIh17IrlrSp/mB0F7Zz" + 
                    "Mt8XUD1Dwz3JrrnxeXnfMvOA5BdUJ9hCyDgMVAGs/IcEEA==", certificateCA               
                )) {
                    string msg2012_512_1 = encoding.GetString(pki2012_512.TestSignedMessage( 
                        "MIIELwYJKoZIhvcNAQcCoIIEIDCCBBwCAQExDDAKBggqhQMHAQECAzA7BgkqhkiG" + 
                        "9w0BBwGgLgQsyu7t8vDu6/zt++kg7/Do7OXwIOTr/yDx8vDz6vLz8PsgU2lnbmVk" + 
                        "RGF0YS6gggIyMIICLjCCAdugAwIBAgIEAYy6hDAKBggqhQMHAQEDAjA4MQ0wCwYD" + 
                        "VQQKEwRUSzI2MScwJQYDVQQDEx5DQSBUSzI2OiBHT1NUIDM0LjEwLTEyIDI1Ni1i" + 
                        "aXQwHhcNMDEwMTAxMDAwMDAwWhcNNDkxMjMxMDAwMDAwWjA7MQ0wCwYDVQQKEwRU" + 
                        "SzI2MSowKAYDVQQDEyFPUklHSU5BVE9SOiBHT1NUIDM0LjEwLTEyIDUxMi1iaXQw" + 
                        "gaAwFwYIKoUDBwEBAQIwCwYJKoUDBwECAQIBA4GEAASBgLSLt1q8KQ4YZVxioU+1" + 
                        "LV9QhE7MHR9gBEh7S1yVNGlqt7+rNG5VFqmrPM74rbUsOlhV8M+zZKprXdk35Oz8" + 
                        "lSW/n2oIUHZxikXIH/SSHj4rv3K/Puvz7hYTQSZl/xPdp78nUmjrEa6d5wfX8biE" + 
                        "y2z0dgufFvAkMw1Ua4gdXqDOo4GHMIGEMGMGA1UdIwRcMFqAFKxsDkxEZqJCluKf" + 
                        "CTslZvPLpFMqoTykOjA4MQ0wCwYDVQQKEwRUSzI2MScwJQYDVQQDEx5DQSBUSzI2" + 
                        "OiBHT1NUIDM0LjEwLTEyIDI1Ni1iaXSCBAGMuoEwHQYDVR0OBBYEFH4GVwmYDK1r" + 
                        "CKhX7nkAWDrJ16CkMAoGCCqFAwcBAQMCA0EACl6p8dAbpi9Hk+3mgMyI0WIh17Ir" + 
                        "lrSp/mB0F7ZzMt8XUD1Dwz3JrrnxeXnfMvOA5BdUJ9hCyDgMVAGs/IcEEDGCAZQw" + 
                        "ggGQAgEBMEAwODENMAsGA1UEChMEVEsyNjEnMCUGA1UEAxMeQ0EgVEsyNjogR09T" + 
                        "VCAzNC4xMC0xMiAyNTYtYml0AgQBjLqEMAoGCCqFAwcBAQIDoIGtMBgGCSqGSIb3" + 
                        "DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE5MTIyNDExMDc0M1ow" + 
                        "IgYJKoZIhvcNAQliMRUEE1NpZ25lZCBhdHRyJ3MgdmFsdWUwTwYJKoZIhvcNAQkE" + 
                        "MUIEQFHTxxLpBeQSH6PQ6ECDHZwdGS5M6tEbnhFGUjb9OwOwvhilohutn7ngK4PL" + 
                        "jwhz01Denf+Nqd934DJBMB+3+3AwCgYIKoUDBwEBAQIEgYAkrNCfwqyNirAexEJm" + 
                        "pnJ6Z/yje4L6l4AUD0+cHf1YsWN1VqVgjmDBXTBu5XI29lUUnis4bejKLgoUPUM+" + 
                        "zFBYqzM27z1K6nV4P2A62+mHT0T12dn21EFDsPKi1NrakbrNCAE994k1+TD0l4zE" + 
                        "A51nxbmE7+PY2wI+QDx+MK0ohg=="                    
                    )); 
                    string msg2012_512_2 = encoding.GetString(pki2012_512.TestEnvelopedMessage( 
                        "MIIB/gYJKoZIhvcNAQcDoIIB7zCCAesCAQIxggFioYIBXgIBA6CBo6GBoDAXBggq" + 
                        "hQMHAQEBAjALBgkqhQMHAQIBAgEDgYQABIGAqMw92ZqXqO6FkoNouow+elnNsutl" + 
                        "ufJEybtE4DpElQ1f+0a0D/DDu2oTgRLsbZZ7wYeE7+M++yvZSEg5d4Z1n6Uzw7BR" + 
                        "W66mIllaWGarQZq9XbvoiFHHE62X1nESH6PHGSvSvIR7tkuiz4k2pJ0r8sNY59uv" + 
                        "FL2d8CUVyhX9tv+hIgQgVVyeD8Ftb0g0hQlgxvui4rN84o9UpTnBi/LcPkwfli8w" + 
                        "FwYJKoUDBwEBBwIBMAoGCCqFAwcBAQYCMHYwdDBAMDgxDTALBgNVBAoTBFRLMjYx" + 
                        "JzAlBgNVBAMTHkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJpdAIEAYy6hQQw" + 
                        "fAL9oTjbuEX7HkZSCbQplXlw2YkBSrNOFmHtGhtmtqE/rDlFAdUAbGjNhUg5r0X3" + 
                        "MF0GCSqGSIb3DQEHATAfBgkqhQMHAQEFAgIwEgQQqsbFj+KRJMOXugOkALKG2YAv" + 
                        "/HJf0ZftDRgXAmTi6RFvEc8wkdQHq/Usa0NCKwwKW60TJZgahc7I+maC5XOL9lGh" + 
                        "ITAfBgkqhQMHAQAGAQExEgQQHyCU9sez1XiyqkKxRJfmeA=="
                    )); 
                    string msg2012_512_3 = encoding.GetString(pki2012_512.TestEnvelopedMessage( 
                        "MIIB5wYJKoZIhvcNAQcDoIIB2DCCAdQCAQIxggFXMIIBUwIBADBAMDgxDTALBgNV" + 
                        "BAoTBFRLMjYxJzAlBgNVBAMTHkNBIFRLMjY6IEdPU1QgMzQuMTAtMTIgMjU2LWJp" + 
                        "dAIEAYy6hTAXBgkqhQMHAQEHAQEwCgYIKoUDBwEBBgIEgfIwge8EKHbLUMg1GlNv" + 
                        "6p4+txIFhp8vlMc5wLkfzyW7HMEYJV300MYIuNOdeMswgaAwFwYIKoUDBwEBAQIw" + 
                        "CwYJKoUDBwECAQIBA4GEAASBgM2u0mhO94tVA/I7uMrNc2xVcedFKsXr8Q7vXt+c" + 
                        "ItEcfV08G7KXKfB2l4aSE//3VpRqNK9qTODen1uFHEDBxzYQ3yA//kpcUhufJb8n" + 
                        "MsgPt9P3EFW0t7lUW9uRImKGf1OWvBgSBUcPEUjpzRO0/rwtB417iqEXE9SOdcYI" + 
                        "LkgVBCCQ92yubQEre9f0iBliLcDU1yJUXLs0gm/FtOijZTw8ETBZBgkqhkiG9w0B" + 
                        "BwEwGwYJKoUDBwEBBQECMA4EDAAzmc8qMWjK2jAZi4AvElakWFy9/Z2cQc3fk7CO" + 
                        "3A5wu4PbfjFjOQuJOiKeECQfCfUxAY4knKP13HvYwxehGTAXBgkqhQMHAQAGAQEx" + 
                        "CgQIAYn04kHEO8o="
                    )); 
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // ГОСТ PKCS12
        ////////////////////////////////////////////////////////////////////////////
        public static class PKCS12
        {
            private static Certificate GetCertificate(String certificateBase64) 
            {
                // получить закодированный сертификат
                byte[] encodedCertificate = Base64.GetDecoder().Decode(certificateBase64);

                // раскодировать сертификат
                return new Certificate(encodedCertificate); 
            }
            private static IPrivateKey GetPrivateKey(
                Factory factory, Certificate certificate, Math.BigInteger d)
            {
                // извлечь открытый ключ
                IPublicKey publicKey = certificate.GetPublicKey(factory); 

                // получить параметры ключа
                GOSTR3410.IECParameters parameters = 
                    (GOSTR3410.IECParameters)publicKey.Parameters; 

                // вернуть личный ключ
                return new GOSTR3410.ECPrivateKey(
                    factory, null, publicKey.KeyOID, parameters, d
                ); 
            }
            private static void Test(Factory factory, 
                CAPI.PKCS12.PfxContainer container, String testCertificateBase64, 
                Object testPrivateKeyObj, byte[] keyID)
            {       
                // найти сертификат
                CAPI.PKCS12.PfxSafeBag certItem = container.FindCertificate(keyID); 

                // проверить наличие сертификата
                if (certItem == null) throw new NotFoundException();

                // извлечь содержимое сертификата
                ASN1.ISO.PKCS.PKCS12.CertBag certBag = new ASN1.ISO.PKCS.PKCS12.CertBag(
                    certItem.Decoded.BagValue
                ); 
                // раскодировать сертификат
                Certificate certificate = new Certificate(certBag.CertValue.Content); 

                // указать сертификат для сравнения
                Certificate testCertificate = GetCertificate(testCertificateBase64); 

                // сравнить сертификаты
                if (!certificate.Equals(testCertificate)) throw new ArgumentException(); 

                // найти личный ключ
                CAPI.PKCS12.PfxSafeBag itemPrivateKey = container.FindPrivateKey(keyID);

                // проверить наличие ключа
                if (itemPrivateKey == null) throw new NotFoundException(); 

                // извлечь содержимое сертификата
                ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo privateKeyInfo = 
                    new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(itemPrivateKey.Decoded.BagValue); 

                // при указании закодированного представленич
                if (testPrivateKeyObj is ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo)
                {
                    // сравнить представления
                    if (!privateKeyInfo.Equals(testPrivateKeyObj)) throw new ArgumentException();
                }
                // раскодировать ключ
                else using (IPrivateKey privateKey = factory.DecodePrivateKey(privateKeyInfo))            
                {
                    // извлечь секретное значение
                    Math.BigInteger d = ((GOSTR3410.IECPrivateKey)privateKey).D; 
                
                    // сравнить личные ключи
                    if (!d.Equals(testPrivateKeyObj)) throw new ArgumentException();
                }
            }
            // выполнить тест
            public static void TestSignedEnveloped(Factory factory, 
                String containerBase64, String senderCertificateBase64, 
                Math.BigInteger senderPrivateKeyD, String recipientCertificateBase64, 
                Math.BigInteger recipientPrivateKeyD, String testCertificateBase64, 
                Math.BigInteger testPrivateKeyD, byte[] keyID) 
            {
                // получить закодированный контейнер
                ASN1.ISO.PKCS.PKCS12.PFX pfx = new ASN1.ISO.PKCS.PKCS12.PFX(
                    ASN1.Encodable.Decode(Base64.GetDecoder().Decode(containerBase64))
                );
                // указать генератор случайных данных
                using (IRand rand = new CAPI.Rand(null))
                {
                    // раскодировать контейнер
                    using (CAPI.PKCS12.PfxSignedEnvelopedContainer container = 
                        new CAPI.PKCS12.PfxSignedEnvelopedContainer(pfx, rand)) 
                    {
                        // раскодировать сертификаты
                        Certificate senderCertificate    = GetCertificate(senderCertificateBase64   ); 
                        Certificate recipientCertificate = GetCertificate(recipientCertificateBase64); 

                        // извлечь личный ключ
                        using (IPrivateKey senderPrivateKey = GetPrivateKey(
                            factory, senderCertificate, senderPrivateKeyD)) 
                        {
                            // извлечь личный ключ
                            using (IPrivateKey recipientPrivateKey = GetPrivateKey(
                                factory, recipientCertificate, recipientPrivateKeyD))
                            {
                                // установить ключи
                                container.SetSignKeys    (senderPrivateKey   , senderCertificate);
                                container.SetEnvelopeKeys(recipientPrivateKey, recipientCertificate, null); 
                            }
                        }
                        // выполнить тест
                        Test(factory, container, testCertificateBase64, testPrivateKeyD, keyID); 
                    }
                }
            }
            // выполнить тест
            public static void TestAuthenticatedEncrypted(Factory factory,
                String containerBase64, String testCertificateBase64, 
                Object testPrivateKeyObj, byte[] keyID) 
            {
                // получить закодированный контейнер
                ASN1.ISO.PKCS.PKCS12.PFX pfx = new ASN1.ISO.PKCS.PKCS12.PFX(
                    ASN1.Encodable.Decode(Base64.GetDecoder().Decode(containerBase64))
                );
                // указать генератор случайных данных
                using (IRand rand = new CAPI.Rand(null))
                {
                    // раскодировать контейнер
                    using (CAPI.PKCS12.PfxAuthenticatedEncryptedContainer container = 
                        new CAPI.PKCS12.PfxAuthenticatedEncryptedContainer(pfx, factory, rand)) 
                    {
                        // указать пароль на контейнер
                        container.SetPassword("Пароль для PFX");

                        // выполнить тест
                        Test(factory, container, testCertificateBase64, testPrivateKeyObj, keyID); 
                    }
                }
            }
            public static void Test(Factory factory) 
            {
                GetCertificate(
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
                GetCertificate(
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
                TestSignedEnveloped(factory, 
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
                    "soqhSf9ycQ==", new Math.BigInteger(1, new byte[] { 
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
                    "lJbyu48wZWpZ", new Math.BigInteger(1, new byte[] { 
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
                    "cg==", new Math.BigInteger(1, new byte[] { 
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
                TestAuthenticatedEncrypted(factory, 
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
                    "cg==", new Math.BigInteger(1, new byte[] { 
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
                    byte[] encodedPrivateKeyInfo = Base64.GetDecoder().Decode(
                        "MGYCAQAwHwYIKoUDBwEBAQEwEwYHKoUDAgIjAQYIKoUDBwEBAgIEQEYbRu86z+1JFKDcPDN9UbTG" +
                        "G2ki9enTqos4KpUU0j9IDpl1UXiaA1YDIwUjlAp+81GkLmyt8Fw6Gt/X5JZySAY="
                    ); 
                    // извлечь описание личного ключа
                    ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo privateKeyInfo = 
                        new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(
                            ASN1.Encodable.Decode(encodedPrivateKeyInfo)
                    ); 
                    // выполнить тест
                    TestAuthenticatedEncrypted(factory, 
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
}

using System;

namespace Aladdin.CAPI.ANSI
{
    public class Test : CAPI.Test
    {
        ///////////////////////////////////////////////////////////////////////
        // Выполнить тесты
        ///////////////////////////////////////////////////////////////////////
        public static void Entry() 
        {
            using (CAPI.Factory factory = new Factory()) 
            { 
                SecurityStore scope = null; 
            
                ////////////////////////////////////////////////////////////////////
                // Алгоритмы хэширования
                ////////////////////////////////////////////////////////////////////
                TestMD2      (factory, scope);
                TestMD4      (factory, scope);
                TestMD5      (factory, scope);
                TestRIPEMD128(factory, scope);
                TestRIPEMD160(factory, scope);
                TestRIPEMD256(factory, scope);
                TestSHA1     (factory, scope);
                TestSHA2_224 (factory, scope);
                TestSHA2_256 (factory, scope);
                TestSHA2_384 (factory, scope);
                TestSHA2_512 (factory, scope);
                TestSHA3_224 (factory, scope);
                TestSHA3_256 (factory, scope);
                TestSHA3_384 (factory, scope);
                TestSHA3_512 (factory, scope);

                ////////////////////////////////////////////////////////////////////
                // Алгоритмы вычисления имитовставки
                ////////////////////////////////////////////////////////////////////
                TestHMAC_MD5      (factory, scope); 
                TestHMAC_RIPEMD128(factory, scope); 
                TestHMAC_RIPEMD160(factory, scope); 
                TestHMAC_SHA1     (factory, scope); 
                TestHMAC_SHA2_224 (factory, scope); 
                TestHMAC_SHA2_256 (factory, scope); 
                TestHMAC_SHA2_384 (factory, scope); 
                TestHMAC_SHA2_512 (factory, scope); 
                TestCBCMAC_DES    (factory, scope, 8); 
                TestCBCMAC_DES    (factory, scope, 4); 
                TestCMAC_AES      (factory, scope); 

                ////////////////////////////////////////////////////////////////////
                // Алгоритмы шифрования
                ////////////////////////////////////////////////////////////////////
                TestSkipjack(factory, scope); 
                TestRC2     (factory, scope); 
                TestRC4     (factory, scope); 
                TestRC5     (factory, scope); 
                TestDES     (factory, scope); 
                TestTDES    (factory, scope); 
                TestAES     (factory, scope); 
            
                ////////////////////////////////////////////////////////////////////
                // Алгоритмы наследования ключа
                ////////////////////////////////////////////////////////////////////
                TestPBKDF2_HMAC_SHA1(factory, scope); 
                TestX942KDF_SHA1    (factory, scope); 

                ////////////////////////////////////////////////////////////////////
                // Алгоритмы шифрования ключа
                ////////////////////////////////////////////////////////////////////
                TestWrapSMIME_DES (factory, scope);
                TestWrapSMIME_TDES(factory, scope);
                TestWrapRC2       (factory, scope); 
                TestWrapTDES      (factory, scope); 
                TestWrapAES       (factory, scope); 

                // указать генератор случайных данных
                using (IRand rand = new CAPI.Rand(null))
                { 
                    ////////////////////////////////////////////////////////////////////
                    // RSA
                    ////////////////////////////////////////////////////////////////////
                    int[] keySizes = KeySizes.Range(1, 32); 

                    TestRSA(factory, scope, rand, true, KeyFlags.None,  384, keySizes); 
                    TestRSA(factory, scope, rand, true, KeyFlags.None,  512, keySizes); 
                    TestRSA(factory, scope, rand, true, KeyFlags.None, 1024, keySizes); 
                    TestRSA(factory, scope, rand, true, KeyFlags.None, 1536, keySizes); 
                    TestRSA(factory, scope, rand, true, KeyFlags.None, 2048, keySizes); 

                    ////////////////////////////////////////////////////////////////////
                    // DSA/DH
                    ////////////////////////////////////////////////////////////////////
                    TestDSA(factory, scope, rand, true, KeyFlags.None); 
                    TestDH (factory, scope, rand, true, KeyFlags.None); 
            
                    ////////////////////////////////////////////////////////////////////
                    // ECDSA/ECDH
                    ////////////////////////////////////////////////////////////////////
                    TestECDSA(factory, null); 

                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2pnb163v1   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2pnb163v2   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2pnb163v3   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2pnb176w1   ); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2tnb191v1   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2tnb191v2   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2tnb191v3   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2onb191v4   ); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2onb191v5   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2pnb208w1   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2tnb239v1   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2tnb239v2   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2tnb239v3   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2onb239v4   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2pnb272w1   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2pnb304w1   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2tnb359v1   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2pnb368w1   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2tnb431r1   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_prime192v1   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_prime192v2   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_prime192v3   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_prime239v1   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_prime239v2   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_prime239v3   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_prime256v1   );
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect163k1); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect163r1); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect239k1);
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect113r1);
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect113r2);
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_secp112r1);
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_secp112r2);
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_secp160r1);
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_secp160k1);
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_secp256k1); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect163r2); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect283k1); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect283r1); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect131r1);
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect131r2);
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect193r1);
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect193r2);
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect233k1); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect233r1); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_secp128r1);
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_secp128r2);
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_secp160r2);
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_secp192k1); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_secp224k1); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_secp224r1); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_secp384r1); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_secp521r1); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect409k1); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect409r1); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect571k1); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.certicom_curves_sect571r1); 
                    TestEC(factory, scope, rand, true, KeyFlags.None, ASN1.ANSI.OID.x962_curves_c2onb239v5   ); 
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование хэш-алгоритмов
        ////////////////////////////////////////////////////////////////////////////
        public static void TestMD2(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Hash.MD2");
        
            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md2), ASN1.Null.Instance
            );
            // создать алгоритм
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters))
            {
                // протестировать алгоритм
                Hash.MD2.Test(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestMD4(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Hash.MD4");
        
            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md4), ASN1.Null.Instance
            );
            // создать алгоритм
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters))
            {
                // протестировать алгоритм
                Hash.MD4.Test(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestMD5(CAPI.Factory factory, SecurityStore scope) 
        {
            WriteLine("Hash.MD5");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md5), ASN1.Null.Instance
            );
            // создать алгоритм
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters))
            {
                // протестировать алгоритм
                Hash.MD5.Test(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestRIPEMD128(CAPI.Factory factory, SecurityStore scope) 
        {
            WriteLine("Hash.RIPEMD128");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_ripemd128), ASN1.Null.Instance
            );
            // создать алгоритм
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters))
            {   
                // протестировать алгоритм
                Hash.RIPEMD128.Test(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestRIPEMD160(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Hash.RIPEMD160");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_ripemd160), ASN1.Null.Instance
            );
            // создать алгоритм
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters))
            {
                // протестировать алгоритм
                Hash.RIPEMD160.Test(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestRIPEMD256(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Hash.RIPEMD256");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_ripemd256), ASN1.Null.Instance
            );
            // создать алгоритм
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters))
            {
                // протестировать алгоритм
                Hash.RIPEMD256.Test(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestSHA1(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Hash.SHA1");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
            );
            // создать алгоритм
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters))
            {
                // протестировать алгоритм
                Hash.SHA1.Test(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestSHA2_224(CAPI.Factory factory, SecurityStore scope) 
        {
            WriteLine("Hash.SHA2_224");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), ASN1.Null.Instance
            );
            // создать алгоритм
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters))
            {
                // протестировать алгоритм
                Hash.SHA2_224.Test(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestSHA2_256(CAPI.Factory factory, SecurityStore scope) 
        {
            WriteLine("Hash.SHA2_256");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
            );
            // создать алгоритм
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters))
            {
                // протестировать алгоритм
                Hash.SHA2_256.Test(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestSHA2_384(CAPI.Factory factory, SecurityStore scope) 
        {
            WriteLine("Hash.SHA2_384");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), ASN1.Null.Instance
            );
            // создать алгоритм
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters))
            {
                // протестировать алгоритм
                Hash.SHA2_384.Test(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestSHA2_512(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Hash.SHA2_512");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), ASN1.Null.Instance
            );
            // создать алгоритм
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters))
            {
                // протестировать алгоритм
                Hash.SHA2_512.Test(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestSHA3_224(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Hash.SHA3_224");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_224), ASN1.Null.Instance
            );
            // создать алгоритм
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters))
            {
                // протестировать алгоритм
                Hash.SHA3.Test224(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestSHA3_256(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Hash.SHA3_256");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_256), ASN1.Null.Instance
            );
            // создать алгоритм
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters))
            {
                // протестировать алгоритм
                Hash.SHA3.Test256(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestSHA3_384(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Hash.SHA3_384");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_384), ASN1.Null.Instance
            );
            // создать алгоритм
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters))
            {
                // протестировать алгоритм
                Hash.SHA3.Test384(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestSHA3_512(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Hash.SHA3_512");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_512), ASN1.Null.Instance
            );
            // создать алгоритм
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, parameters))
            {
                // протестировать алгоритм
                Hash.SHA3.Test512(hashAlgorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // протестировать алгоритм
                    HashTest(hashAlgorithm, trustFactory, null, parameters); 
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование алгоритмов вычисления имитовставки
        ////////////////////////////////////////////////////////////////////////////
        public static void TestHMAC_MD5(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("MAC.HMAC_MD5");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ipsec_hmac_md5), ASN1.Null.Instance
            ); 
            // создать алгоритм 
            using (Mac algorithm = factory.CreateAlgorithm<Mac>(scope, parameters))
            {
                // выполнить тест
                Hash.MD5.TestHMAC(algorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // указать допустимые размеры
                    int[] dataSizes = new int[] { 0, 1, 63, 64, 65 }; 

                    // выполнить тест
                    MacTest(algorithm, trustFactory, null, parameters, dataSizes); 
                }
            }
        }
        public static void TestHMAC_RIPEMD128(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("MAC.HMAC_RIPEMD128");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_ripemd128), ASN1.Null.Instance
            ); 
            // получить алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
            {
                // проверить наличие алгоритма хэширования
                if (hashAlgorithm == null) return; 

                // создать алгоритм
                using (Mac algorithm = new MAC.HMAC(hashAlgorithm))
                {
                    // выполнить тест
                    Hash.RIPEMD128.TestHMAC(algorithm);
                }
            }
        }
        public static void TestHMAC_RIPEMD160(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("MAC.HMAC_RIPEMD160");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ipsec_hmac_ripemd160), ASN1.Null.Instance
            ); 
            // создать алгоритм 
            using (Mac algorithm = factory.CreateAlgorithm<Mac>(scope, parameters))
            {
                // выполнить тест
                Hash.RIPEMD160.TestHMAC(algorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // указать допустимые размеры
                    int[] dataSizes = new int[] { 0, 1, 63, 64, 65 }; 

                    // выполнить тест
                    MacTest(algorithm, trustFactory, null, parameters, dataSizes); 
                }
            }
        }
        public static void TestHMAC_SHA1(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("MAC.HMAC_SHA1");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_hmac_sha1), ASN1.Null.Instance
            ); 
            // создать алгоритм 
            using (Mac algorithm = factory.CreateAlgorithm<Mac>(scope, parameters))
            {
                // выполнить тест
                Hash.SHA1.TestHMAC(algorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // указать допустимые размеры
                    int[] dataSizes = new int[] { 0, 1, 63, 64, 65 }; 

                    // выполнить тест
                    MacTest(algorithm, trustFactory, null, parameters, dataSizes); 
                }
            }
        }
        public static void TestHMAC_SHA2_224(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("MAC.HMAC_SHA2_224");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_hmac_sha2_224), ASN1.Null.Instance
            ); 
            // создать алгоритм 
            using (Mac algorithm = factory.CreateAlgorithm<Mac>(scope, parameters))
            {
                // выполнить тест
                Hash.SHA2_224.TestHMAC(algorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // указать допустимые размеры
                    int[] dataSizes = new int[] { 0, 1, 63, 64, 65 }; 

                    // выполнить тест
                    MacTest(algorithm, trustFactory, null, parameters, dataSizes); 
                }
            }
        }
        public static void TestHMAC_SHA2_256(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("MAC.HMAC_SHA2_256");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_hmac_sha2_256), ASN1.Null.Instance
            ); 
            // создать алгоритм 
            using (Mac algorithm = factory.CreateAlgorithm<Mac>(scope, parameters))
            {
                // выполнить тест
                Hash.SHA2_256.TestHMAC(algorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // указать допустимые размеры
                    int[] dataSizes = new int[] { 0, 1, 63, 64, 65 }; 

                    // выполнить тест
                    MacTest(algorithm, trustFactory, null, parameters, dataSizes); 
                }
            }
        }
        public static void TestHMAC_SHA2_384(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("MAC.HMAC_SHA2_384");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_hmac_sha2_384), ASN1.Null.Instance
            ); 
            // создать алгоритм 
            using (Mac algorithm = factory.CreateAlgorithm<Mac>(scope, parameters))
            {
                // выполнить тест
                Hash.SHA2_384.TestHMAC(algorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // указать допустимые размеры
                    int[] dataSizes = new int[] { 0, 1, 127, 128, 129 }; 

                    // выполнить тест
                    MacTest(algorithm, trustFactory, null, parameters, dataSizes); 
                }
            }
        }
        public static void TestHMAC_SHA2_512(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("MAC.HMAC_SHA2_512");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_hmac_sha2_512), ASN1.Null.Instance
            ); 
            // создать алгоритм 
            using (Mac algorithm = factory.CreateAlgorithm<Mac>(scope, parameters))
            {
                // выполнить тест
                Hash.SHA2_512.TestHMAC(algorithm);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // указать допустимые размеры
                    int[] dataSizes = new int[] { 0, 1, 127, 128, 129 }; 

                    // выполнить тест
                    MacTest(algorithm, trustFactory, null, parameters, dataSizes); 
                }
            }
        }
        public static void TestCBCMAC_DES(CAPI.Factory factory, SecurityStore scope, int macSize) 
        {
            WriteLine("MAC.CBCMAC_DES"); 
        
            // указать параметры алгоритма
	        ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_mac),
                new ASN1.Integer(macSize * 8)
            ); 
            // создать алгоритм выработки имитовставки
            using (Mac algorithm = factory.CreateAlgorithm<Mac>(scope, parameters))
            {
                // указать доверенную фабрику
                using (Factory trustFactory = new ANSI.Factory()) 
                { 
                    // указать допустимые размеры
                    int[] dataSizes = new int[] { 0, 8, 16 }; 

                    // выполнить тест
                    MacTest(algorithm, trustFactory, null, parameters, dataSizes); 
                }
            }
        }
        public static void TestCMAC_AES(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("MAC.CMAC_AES");

            // создать блочный алгоритм шифрования
            using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                scope, "AES", ASN1.Null.Instance))
            {
                // создать алгоритм выработки имитовставки
                using (Mac algorithm = MAC.OMAC1.Create(blockCipher, new byte[16], 16))
                {
                    // протестировать алгоритм
                    Engine.AES.Test128_CMAC(algorithm);
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование алгоритмов шифрования
        ////////////////////////////////////////////////////////////////////////////
        public static void TestSkipjack(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Cipher.Skipjack");

		    // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.infosec_skipjack_cbc), 
                new ASN1.ANSI.SkipjackParm(new ASN1.OctetString(new byte[8]))
            ); 
            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
            {
                // выполнить тест
                Engine.Skipjack.Test(cipher); 
            }
        }
        public static void TestRC2(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Cipher.RC2");

            // указать идентификатор алгоритма
            ASN1.ObjectIdentifier oid = new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_rc2_ecb);
        
            // закодировать параметры алгоритма
            ASN1.IEncodable engineParameters = ASN1.ANSI.RSA.RC2ParameterVersion.GetVersion(63);  
        
            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(oid, engineParameters); 
            
            // создать алгоритм шифрования
            using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
            {
                // выполнить тест
                if (engine != null) Engine.RC2.Test63(engine); 
            
                // указать доверенную фабрику
                if (engine != null) using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // выполнить тест
                    CipherTest(engine, trustFactory, null, parameters); 
                }
            }
            // закодировать параметры алгоритма
            engineParameters = ASN1.ANSI.RSA.RC2ParameterVersion.GetVersion(64);  
        
            // указать параметры алгоритма
            parameters = new ASN1.ISO.AlgorithmIdentifier(oid, engineParameters); 
            
            // создать алгоритм шифрования
            using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
            {
                // выполнить тест
                if (engine != null) Engine.RC2.Test64(engine); 

                // указать доверенную фабрику
                if (engine != null) using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // выполнить тест
                    CipherTest(engine, trustFactory, null, parameters); 
                }
            }
            // закодировать параметры алгоритма
            engineParameters = ASN1.ANSI.RSA.RC2ParameterVersion.GetVersion(128);  
        
            // указать параметры алгоритма
            parameters = new ASN1.ISO.AlgorithmIdentifier(oid, engineParameters); 
            
            // создать алгоритм шифрования
            using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
            {
                // выполнить тест
                if (engine != null) Engine.RC2.Test128(engine); 

                // указать доверенную фабрику
                if (engine != null) using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // выполнить тест
                    CipherTest(engine, trustFactory, null, parameters); 
                }
            }
            // закодировать параметры алгоритма
            engineParameters = ASN1.ANSI.RSA.RC2ParameterVersion.GetVersion(129);  
        
            // указать параметры алгоритма
            parameters = new ASN1.ISO.AlgorithmIdentifier(oid, engineParameters); 
            
            // создать алгоритм шифрования
            using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
            {
                // выполнить тест
                if (engine != null) Engine.RC2.Test129(engine); 
            
                // указать доверенную фабрику
                if (engine != null) using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // выполнить тест
                    CipherTest(engine, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestRC4(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Cipher.RC4");

            // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_rc4), ASN1.Null.Instance
            ); 
            // создать алгоритм шифрования
            using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
            {
                // выполнить тест
                Cipher.RC4.Test(cipher);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // указать допустимые размеры
                    int[] dataSizes = new int[] { 0, 1, 63, 64, 65, 127, 128, 129 }; 

                    // выполнить тест
                    CipherTest(cipher, PaddingMode.None, trustFactory, null, parameters, dataSizes); 
                }
            }
        }
        public static void TestRC5(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Cipher.RC5");

            // указать тестируемое число раундов
            int[] rounds = new int[] { 0, 1, 2, 8, 12, 16 }; 
        
            // сгенерировать случайную синхропосылку
            byte[] iv = new byte[8]; Generate(iv, 0, iv.Length); 
        
            // для всех тестируемых раундов
            for (int i = 0; i < rounds.Length; i++)
            {
                // закодировать параметры алгоритма
                ASN1.IEncodable cipherParameters = new ASN1.ANSI.RSA.RC5CBCParameter(
    			    new ASN1.Integer(16), new ASN1.Integer(rounds[i]), 
                    new ASN1.Integer(64), new ASN1.OctetString(iv)
                ); 
                // указать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_rc5_cbc), cipherParameters
                ); 
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) continue; 
                
                    // указать доверенную фабрику
                    using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                    { 
                        // выполнить тест
                        CipherTest(cipher, trustFactory, null, parameters); 
                    }
                }
                // создать блочный алгоритм шифрования
                using (IBlockCipher blockCipher = new Cipher.RC5(factory, scope, 8, rounds[i]))
                {
                    switch (rounds[i])
                    { 
                    case  0: Engine.RC5_64.Test0 (blockCipher); break; 
                    case  1: Engine.RC5_64.Test1 (blockCipher); break; 
                    case  2: Engine.RC5_64.Test2 (blockCipher); break; 
                    case  8: Engine.RC5_64.Test8 (blockCipher); break; 
                    case 12: Engine.RC5_64.Test12(blockCipher); break; 
                    case 16: Engine.RC5_64.Test16(blockCipher); break; 
                    }
                }
                // указать параметры алгоритма
                parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_rc5_cbc_pad), cipherParameters
                ); 
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) continue; 
                
                    // указать доверенную фабрику
                    using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                    { 
                        // указать допустимые размеры
                        int[] dataSizes = new int[] { 0, 1, 7, 8, 9, 15, 16, 17 }; 

                        // выполнить тест
                        CipherTest(cipher, PaddingMode.Any, trustFactory, null, parameters, dataSizes); 
                    }
                }
            }
        }
        public static void TestDES(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Cipher.DES");

            // указать параметры алгоритма
	        ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_ecb), ASN1.Null.Instance
            ); 
            // создать алгоритм шифрования
            using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
            {
                // выполнить тест
                Engine.DES.Test(engine);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // выполнить тест
                    CipherTest(engine, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestTDES(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Cipher.TDES");

            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_tdes_ecb), ASN1.Null.Instance); 
        
            // создать алгоритм шифрования
            using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
            {
                // выполнить тест
                Engine.TDES.Test(engine);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // выполнить тест
                    CipherTest(engine, trustFactory, null, parameters); 
                }
            }
        }
        public static void TestAES(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("Cipher.AES");

            // указать параметры алгоритма
	        ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_ecb), ASN1.Null.Instance
            ); 
            // создать алгоритм шифрования
            using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
            {
                // выполнить тест
                if (engine != null) Engine.AES.Test128(engine);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // выполнить тест
                    CipherTest(engine, trustFactory, null, parameters); 
                }
            }
	        // указать параметры алгоритма
	        parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes192_ecb), ASN1.Null.Instance
            ); 
            // создать алгоритм шифрования
            using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
            {
                // выполнить тест
                if (engine != null) Engine.AES.Test192(engine);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // выполнить тест
                    CipherTest(engine, trustFactory, null, parameters); 
                }
            }
	        // указать параметры алгоритма
	        parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_ecb), ASN1.Null.Instance
            ); 
            // создать алгоритм шифрования
            using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
            {
                // выполнить тест
                if (engine != null) Engine.AES.Test256(engine);
            
                // указать доверенную фабрику
                using (CAPI.Factory trustFactory = new ANSI.Factory()) 
                { 
                    // выполнить тест
                    CipherTest(engine, trustFactory, null, parameters); 
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование алгоритмов наследования ключа
        ////////////////////////////////////////////////////////////////////////////
        public static void TestPBKDF2_HMAC_SHA1(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("KeyDerive.PBKDF2_HMAC_SHA1");
        
            // выполнить тест
            Hash.SHA1.TestHMAC_PBKDF2(factory, scope); 
        }
        public static void TestX942KDF_SHA1(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("KeyDerive.X942KDF_SHA1");

            // закодировать параметры алгоритма хэширования
		    ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
			    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
            ); 
            // создать алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters)) 
            {
                // выполнить тест
                if (hashAlgorithm != null) Derive.X942KDF.TestSHA1(hashAlgorithm);
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование алгоритмов шифрования ключа
        ////////////////////////////////////////////////////////////////////////////
        public static void TestWrapSMIME_DES(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("KeyWrap.SMIME_DES");

            // указать алгоритм шифрования
            using (IBlockCipher des = factory.CreateAlgorithm<IBlockCipher>(
                scope, "DES", ASN1.Null.Instance))
            {
                // выполнить тест
                Engine.DES.TestSMIME(des);
            }
        }
        public static void TestWrapSMIME_TDES(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("KeyWrap.SMIME_TDES");

            // указать алгоритм шифрования
            using (IBlockCipher tdes = factory.CreateAlgorithm<IBlockCipher>(
                scope, "DESede", ASN1.Null.Instance))
            {
                // выполнить тест
                Engine.TDES.TestSMIME(tdes);
            }
        }
        public static void TestWrapRC2(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("KeyWrap.RC2");

            // указать идентификатор алгоритма
            ASN1.ObjectIdentifier oid = new ASN1.ObjectIdentifier(
                ASN1.ISO.PKCS.PKCS9.OID.smime_rc2_128_wrap
            ); 
            // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                oid, ASN1.ANSI.RSA.RC2ParameterVersion.GetVersion(40)
            );
            // создать алгоритм
            using (KeyWrap algorithm = factory.CreateAlgorithm<KeyWrap>(scope, parameters))
            {
                // выполнить тест
                if (algorithm != null) Wrap.RC2.Test40(algorithm);
            }
            // указать параметры алгоритма
		    parameters = new ASN1.ISO.AlgorithmIdentifier(
                oid, ASN1.ANSI.RSA.RC2ParameterVersion.GetVersion(128)
            );
            // создать алгоритм
            using (KeyWrap algorithm = factory.CreateAlgorithm<KeyWrap>(scope, parameters))
            {
                // выполнить тест
                if (algorithm != null) Wrap.RC2.Test128(algorithm);
            }
        }
        public static void TestWrapTDES(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("KeyWrap.TDES");

            // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.smime_tdes192_wrap), 
                ASN1.Null.Instance
            );
            // создать алгоритм
            using (KeyWrap algorithm = factory.CreateAlgorithm<KeyWrap>(scope, parameters))            
            {
                // выполнить тест
                Wrap.TDES.Test(algorithm); 
            }
        }
        public static void TestWrapAES(CAPI.Factory factory, SecurityStore scope)
        {
            WriteLine("KeyWrap.AES");

            // указать параметры алгоритма
		    ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_wrap), ASN1.Null.Instance
            );
            // создать алгоритм
            using (KeyWrap algorithm = factory.CreateAlgorithm<KeyWrap>(scope, parameters))
            {
                // выполнить тест
                if (algorithm != null) Wrap.AES.Test(algorithm);
            }
            // указать параметры алгоритма
		    parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_wrap_pad), ASN1.Null.Instance
            );
            // создать алгоритм
            using (KeyWrap algorithm = factory.CreateAlgorithm<KeyWrap>(scope, parameters))
            {
                // выполнить тест
                if (algorithm != null) Wrap.AES_PAD.Test(algorithm);
            }
            // указать параметры алгоритма
		    parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes192_wrap), ASN1.Null.Instance
            );
            // создать алгоритм
            using (KeyWrap algorithm = factory.CreateAlgorithm<KeyWrap>(scope, parameters))
            {
                // выполнить тест
                if (algorithm != null) Wrap.AES.Test(algorithm);
            }
            // указать параметры алгоритма
		    parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes192_wrap_pad), ASN1.Null.Instance
            );
            // создать алгоритм
            using (KeyWrap algorithm = factory.CreateAlgorithm<KeyWrap>(scope, parameters))
            {
                // выполнить тест
                if (algorithm != null) Wrap.AES_PAD.Test(algorithm);
            }
            // указать параметры алгоритма
		    parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_wrap), ASN1.Null.Instance
            );
            // создать алгоритм
            using (KeyWrap algorithm = factory.CreateAlgorithm<KeyWrap>(scope, parameters))
            {
                // выполнить тест
                if (algorithm != null) Wrap.AES.Test(algorithm);
            }
            // указать параметры алгоритма
		    parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_wrap_pad), ASN1.Null.Instance
            );
            // создать алгоритм
            using (KeyWrap algorithm = factory.CreateAlgorithm<KeyWrap>(scope, parameters))
            {
                // выполнить тест
                if (algorithm != null) Wrap.AES_PAD.Test(algorithm);
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование RSA
        ////////////////////////////////////////////////////////////////////////////
        public static void TestRSA(CAPI.Factory factory, SecurityObject scope, 
            IRand rand, bool generate, KeyFlags keyFlags, int bits, int[] keySizes)
        {
            WriteLine("RSA/{0}", bits);

            // указать идентификатор ключа
            String keyOID = ASN1.ISO.PKCS.PKCS1.OID.rsa; 

            // указать доверенную фабрику
            using (CAPI.Factory trustFactory = new ANSI.Factory()) 
            { 
                // получить фабрику кодирования ключа
                KeyFactory keyFactory = trustFactory.GetKeyFactory(keyOID); 
        
                // указать способ использования ключа
                KeyUsage keyUsage = keyFactory.GetKeyUsage(); 
        
                // указать параметры ключа
                IParameters parameters = new RSA.Parameters(bits); 

                // сгенерировать ключевую пару
                using (KeyPair keyPair = GenerateKeyPair(
                    factory, scope, rand, trustFactory, null, generate, 
                    keyOID, parameters, keyUsage, keyFlags)) 
                try {
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.DigitalSignature) != KeyUsage.None)
                    { 
                        // выполнить тесты
                        TestSignRSA(trustFactory, null, keyPair, keyFlags); 
                    }
                    // при допустимости теста
                    if (((keyUsage & KeyUsage.DataEncipherment) != KeyUsage.None) || 
                        ((keyUsage & KeyUsage.KeyEncipherment ) != KeyUsage.None))
                    { 
                        // выполнить тесты
                        TestKeyxRSA(trustFactory, null, keyPair, keyFlags, keySizes); 
                    }
                }
                // удалить ключи контейнера
                finally { DeleteKeys(scope); }
            }
            WriteLine();
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование подписи RSA
        ////////////////////////////////////////////////////////////////////////////
        private static bool HashSupportedRSA_PKCS1(
            IPublicKey publicKey, ASN1.ISO.AlgorithmIdentifier hashParameters, int hashSize)
        {
            // преобразовать тип ключа
            RSA.IPublicKey rsaPublicKey = (RSA.IPublicKey)publicKey; 

            // определить размер модуля в байтах
            int k = (rsaPublicKey.Modulus.BitLength + 7) / 8; 

            // закодировать хэш-значение 
            ASN1.ISO.PKCS.DigestInfo digestInfo = new ASN1.ISO.PKCS.DigestInfo(
                hashParameters, new ASN1.OctetString(new byte[hashSize])
            ); 
            // проверить размер хэш-значения
            return (digestInfo.Encoded.Length <= k - 11);
        }  
        // поддержка подписи хэш-значения
        private static bool HashSupportedRSA_PSS(
            IPublicKey publicKey, int hashSize, int saltLength)
        {
            // преобразовать тип ключа
            RSA.IPublicKey rsaPublicKey = (RSA.IPublicKey)publicKey; 

            // определить размер модуля в байтах
            int emLen = (rsaPublicKey.Modulus.BitLength - 1 + 7) / 8; 
        
            // определить размер хэш-значения и salt-значения
            return emLen >= saltLength + hashSize + 2; 
        }
        public static void TestSignRSA(CAPI.Factory factory, 
            SecurityStore scope, KeyPair keyPair, KeyFlags keyFlags)
        {
            // закодировать параметры алгоритма подписи
            ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
            );
            // закодировать параметры алгоритма хэширования
            ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md2), ASN1.Null.Instance
            );
            // указать параметры алгоритма подписи данных
            ASN1.ISO.AlgorithmIdentifier signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_rsa_md2), null
            );
            // получить алгоритм подписи данных
            using (SignData signAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<SignData>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedRSA_PKCS1(
                    keyPair.PublicKey, hashParameters, 16))
                {
                    // выполнить тест
                    SignTest(factory, scope, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags
                    ); 
                }
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedRSA_PSS(keyPair.PublicKey, 16, 20))
                { 
                    // выполнить тест
                    TestSignRSA_PSS(factory, scope, keyPair, keyFlags, hashParameters, 20); 
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md4), ASN1.Null.Instance
            );
            // указать параметры алгоритма подписи данных
            signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_rsa_md4), null
            );
            // получить алгоритм подписи данных
            using (SignData signAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<SignData>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedRSA_PKCS1(
                    keyPair.PublicKey, hashParameters, 16))
                {
                    // выполнить тест
                    SignTest(factory, scope, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags
                    ); 
                }
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedRSA_PSS(keyPair.PublicKey, 16, 20))
                { 
                    // выполнить тест
                    TestSignRSA_PSS(factory, scope, keyPair, keyFlags, hashParameters, 20); 
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md5), ASN1.Null.Instance
            );
            // указать параметры алгоритма подписи данных
            signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_rsa_md5), null
            );
            // получить алгоритм подписи данных
            using (SignData signAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<SignData>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedRSA_PKCS1(
                    keyPair.PublicKey, hashParameters, 16))
                {
                    // выполнить тест
                    SignTest(factory, scope, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags
                    ); 
                }
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedRSA_PSS(keyPair.PublicKey, 16, 20))
                { 
                    // выполнить тест
                    TestSignRSA_PSS(factory, scope, keyPair, keyFlags, hashParameters, 20); 
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
            );
            // указать параметры алгоритма подписи данных
            signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1), null
            );
            // получить алгоритм подписи данных
            using (SignData signAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<SignData>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedRSA_PKCS1(
                    keyPair.PublicKey, hashParameters, 20))
                {
                    // выполнить тест
                    SignTest(factory, scope, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags
                    ); 
                }
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedRSA_PSS(keyPair.PublicKey, 20, 20))
                { 
                    // выполнить тест
                    TestSignRSA_PSS(factory, scope, keyPair, keyFlags, hashParameters, 20); 
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
            );
            // указать параметры алгоритма подписи данных
            signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_256), null
            );
            // получить алгоритм подписи данных
            using (SignData signAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<SignData>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedRSA_PKCS1(
                    keyPair.PublicKey, hashParameters, 32))
                {
                    // выполнить тест
                    SignTest(factory, scope, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags
                    ); 
                }
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedRSA_PSS(keyPair.PublicKey, 32, 20))
                { 
                    // выполнить тест
                    TestSignRSA_PSS(factory, scope, keyPair, keyFlags, hashParameters, 20); 
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), ASN1.Null.Instance
            );
            // указать параметры алгоритма подписи данных
            signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_384), null
            );
            // получить алгоритм подписи данных
            using (SignData signAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<SignData>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedRSA_PKCS1(
                    keyPair.PublicKey, hashParameters, 48))
                {
                    // выполнить тест
                    SignTest(factory, scope, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags
                    ); 
                }
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedRSA_PSS(keyPair.PublicKey, 48, 20))
                { 
                    // выполнить тест
                    TestSignRSA_PSS(factory, scope, keyPair, keyFlags, hashParameters, 20); 
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), ASN1.Null.Instance
            );
            // указать параметры алгоритма подписи данных
            signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_512), null
            );
            // получить алгоритм подписи данных
            using (SignData signAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<SignData>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedRSA_PKCS1(
                    keyPair.PublicKey, hashParameters, 64))
                {
                    // выполнить тест
                    SignTest(factory, scope, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags
                    ); 
                }
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedRSA_PSS(keyPair.PublicKey, 64, 20))
                { 
                    // выполнить тест
                    TestSignRSA_PSS(factory, scope, keyPair, keyFlags, hashParameters, 20); 
                }
            }
        }
        private static void TestSignRSA_PSS(CAPI.Factory factory, SecurityStore scope,
            KeyPair keyPair, KeyFlags keyFlags, ASN1.ISO.AlgorithmIdentifier hashParameters, int saltLength)
        {
            // закодировать параметры алгоритма генерации маски
            ASN1.ISO.AlgorithmIdentifier maskParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa_mgf1), hashParameters
            ); 
            // закодировать параметры алгоритма подписи
            ASN1.ISO.AlgorithmIdentifier signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa_pss), 
                new ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams(
                    hashParameters, maskParameters, new ASN1.Integer(saltLength), new ASN1.Integer(1)
                )
            ); 
            // получить алгоритм выработки подписи
            using (SignHash signHash = keyPair.PrivateKey.Factory.
                CreateAlgorithm<SignHash>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                // проверить поддержку алгоритма
                if (signHash == null) return; 
            }
            // выполнить тест
            SignTest(factory, scope, hashParameters, 
                signParameters, signParameters, keyPair, keyFlags
            ); 
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование обмена ключами RSA
        ////////////////////////////////////////////////////////////////////////////
        private static int MaxDataSizeRSA_PKCS1(IPublicKey publicKey)
        {
            // преобразовать тип ключа
            RSA.IPublicKey rsaPublicKey = (RSA.IPublicKey)publicKey; 

            // вычислить максимальный размер данных
            return (rsaPublicKey.Modulus.BitLength + 7) / 8 - 11; 
        }
        private static int MaxDataSizeRSA_OAEP(IPublicKey publicKey, int hashSize)
        {
            // преобразовать тип ключа
            RSA.IPublicKey rsaPublicKey = (RSA.IPublicKey)publicKey; 

            // определить размер модуля в байтах
            int k = (rsaPublicKey.Modulus.BitLength + 7) / 8; 
        
            // вернуть максимальный размер данных
            return k - 2 * hashSize - 2;
        }
        public static void TestKeyxRSA(CAPI.Factory factory, SecurityStore scope,
            KeyPair keyPair, KeyFlags keyFlags, int[] keySizes)
        {
            TestKeyxRSA_PKCS1(factory, scope, keyPair, keyFlags, keySizes); 
            TestKeyxRSA_OAEP (factory, scope, keyPair, keyFlags, keySizes); 
        }
        private static void TestKeyxRSA_PKCS1(CAPI.Factory factory, SecurityStore scope,
            KeyPair keyPair, KeyFlags keyFlags, int[] keySizes)
        {
            // закодировать параметры алгоритма 
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
            );
            // вычислить максимальный размер данных
            int dataSize = MaxDataSizeRSA_PKCS1(keyPair.PublicKey); if (dataSize > 0)
            {        
                // выполнить тест
                CiphermentTest(factory, scope, parameters, keyPair, keyFlags, dataSize, keySizes);
            }
        }
        private static void TestKeyxRSA_OAEP(CAPI.Factory factory, SecurityStore scope,
            KeyPair keyPair, KeyFlags keyFlags, int[] keySizes)
        {
            // закодировать параметры алгоритма хэширования
            ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md2), ASN1.Null.Instance
            );
            // получить алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<CAPI.Hash>(keyPair.PrivateKey.Scope, hashParameters)) 
            {
                // вычислить максимальный размер данных
                int dataSize = MaxDataSizeRSA_OAEP(keyPair.PublicKey, 16); 
            
                // при поддержке алгоритма
                if (hashAlgorithm != null && dataSize > 0)
                {
                    // выполнить тест
                    TestKeyxRSA_OAEP(factory, scope, keyPair, 
                        keyFlags, hashParameters, dataSize, keySizes
                    );
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md4), ASN1.Null.Instance
            );
            // получить алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<CAPI.Hash>(keyPair.PrivateKey.Scope, hashParameters)) 
            {
                // вычислить максимальный размер данных
                int dataSize = MaxDataSizeRSA_OAEP(keyPair.PublicKey, 16); 
            
                // при поддержке алгоритма
                if (hashAlgorithm != null && dataSize > 0)
                {
                    // выполнить тест
                    TestKeyxRSA_OAEP(factory, scope, keyPair, 
                        keyFlags, hashParameters, dataSize, keySizes
                    );
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md5), ASN1.Null.Instance
            );
            // получить алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<CAPI.Hash>(keyPair.PrivateKey.Scope, hashParameters)) 
            {
                // вычислить максимальный размер данных
                int dataSize = MaxDataSizeRSA_OAEP(keyPair.PublicKey, 16); 
            
                // при поддержке алгоритма
                if (hashAlgorithm != null && dataSize > 0)
                {
                    // выполнить тест
                    TestKeyxRSA_OAEP(factory, scope, keyPair, 
                        keyFlags, hashParameters, dataSize, keySizes
                    );
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
            );
            // получить алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<CAPI.Hash>(keyPair.PrivateKey.Scope, hashParameters)) 
            {
                // вычислить максимальный размер данных
                int dataSize = MaxDataSizeRSA_OAEP(keyPair.PublicKey, 20); 
            
                // при поддержке алгоритма
                if (hashAlgorithm != null && dataSize > 0)
                {
                    // выполнить тест
                    TestKeyxRSA_OAEP(factory, scope, keyPair, 
                        keyFlags, hashParameters, dataSize, keySizes
                    );
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
            );
            // получить алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<CAPI.Hash>(keyPair.PrivateKey.Scope, hashParameters)) 
            {
                // вычислить максимальный размер данных
                int dataSize = MaxDataSizeRSA_OAEP(keyPair.PublicKey, 32); 
            
                // при поддержке алгоритма
                if (hashAlgorithm != null && dataSize > 0)
                {
                    // выполнить тест
                    TestKeyxRSA_OAEP(factory, scope, keyPair, 
                        keyFlags, hashParameters, dataSize, keySizes
                    );
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), ASN1.Null.Instance
            );
            // получить алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<CAPI.Hash>(keyPair.PrivateKey.Scope, hashParameters)) 
            {
                // вычислить максимальный размер данных
                int dataSize = MaxDataSizeRSA_OAEP(keyPair.PublicKey, 48); 
            
                // при поддержке алгоритма
                if (hashAlgorithm != null && dataSize > 0)
                {
                    // выполнить тест
                    TestKeyxRSA_OAEP(factory, scope, keyPair, 
                        keyFlags, hashParameters, dataSize, keySizes
                    );
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), ASN1.Null.Instance
            );
            // получить алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<CAPI.Hash>(keyPair.PrivateKey.Scope, hashParameters)) 
            {
                // вычислить максимальный размер данных
                int dataSize = MaxDataSizeRSA_OAEP(keyPair.PublicKey, 64); 
            
                // при поддержке алгоритма
                if (hashAlgorithm != null && dataSize > 0)
                {
                    // выполнить тест
                    TestKeyxRSA_OAEP(factory, scope, keyPair, 
                        keyFlags, hashParameters, dataSize, keySizes
                    );
                }
            }
        }
        private static void TestKeyxRSA_OAEP(CAPI.Factory factory, 
            SecurityStore scope, KeyPair keyPair, KeyFlags keyFlags, 
            ASN1.ISO.AlgorithmIdentifier hashParameters, int dataSize, int[] keySizes)
        {
            // закодировать параметры алгоритма генерации маски
            ASN1.ISO.AlgorithmIdentifier maskParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa_mgf1), hashParameters
            ); 
            // закодировать параметры алгоритма 
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa_oaep), 
                new ASN1.ISO.PKCS.PKCS1.RSAESOAEPParams(
                    hashParameters, maskParameters, null
                )
            ); 
            // выполнить тест
            CiphermentTest(factory, scope, parameters, keyPair, keyFlags, dataSize, keySizes);
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование DSA
        ////////////////////////////////////////////////////////////////////////////
        private static bool HashSupportedDSA(IParameters parameters, int hashSize) 
        { 
            // выполнить преобразование типа
            X957.IParameters dsaParameters = (X957.IParameters)parameters; 

            // проверить размер хэш-значения
            return (hashSize * 8 <= dsaParameters.Q.BitLength); 
        }
        public static void TestDSA(CAPI.Factory factory, SecurityObject scope,
            IRand rand, bool generate, KeyFlags keyFlags)
        {
            WriteLine("DSA/EPHEMERAL");

            // указать идентификатор ключа
            String keyOID = ASN1.ANSI.OID.x957_dsa; 
        
            // указать способ использования ключа
            KeyUsage keyUsage = KeyUsage.DigitalSignature; 
        
            // указать доверенную фабрику
            using (CAPI.Factory trustFactory = new ANSI.Factory()) 
            { 
                // получить фабрику кодирования
                KeyFactory keyFactory = trustFactory.GetKeyFactory(keyOID); 

                // раскодировать параметры алгоритма
                IParameters parameters = keyFactory.DecodeParameters(
                    ASN1.ANSI.X957.DssParms.Ephemeral
                ); 
                // сгенерировать ключевую пару
                using (KeyPair keyPair = GenerateKeyPair(
                    factory, scope, rand, trustFactory, null, generate, 
                    keyOID, parameters, keyUsage, keyFlags))
                try {
                    // выполнить тест
                    TestDSA(trustFactory, null, keyPair, keyFlags); 
                }
                // удалить ключи контейнера
                finally { DeleteKeys(scope); }
            }
            WriteLine();
        }
        public static void TestDSA(CAPI.Factory factory, 
            SecurityStore scope, KeyPair keyPair, KeyFlags keyFlags)
        {
            // закодировать параметры алгоритма подписи
            ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x957_dsa), ASN1.Null.Instance
            );
            // закодировать параметры алгоритма хэширования
            ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
            );
            // указать параметры алгоритма подписи данных
            ASN1.ISO.AlgorithmIdentifier signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x957_dsa_sha1), null
            );
            // получить алгоритм подписи данных
            using (SignData signAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<SignData>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                if (signAlgorithm != null) SignTest(factory, scope, 
                    hashParameters, signHashParameters, signParameters, keyPair, keyFlags
                ); 
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), ASN1.Null.Instance
            );
            // указать параметры алгоритма подписи данных
            signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_dsa_sha2_224), null
            );
            // получить алгоритм подписи данных
            using (SignData signAlgorithm = keyPair.PrivateKey.Factory.
               CreateAlgorithm<SignData>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedDSA(keyPair.PublicKey.Parameters, 28))
                {
                    // выполнить тест
                    SignTest(factory, scope, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags
                    ); 
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
            );
            // указать параметры алгоритма подписи данных
            signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_dsa_sha2_256), null
            );
            // получить алгоритм подписи данных
            using (SignData signAlgorithm = keyPair.PrivateKey.Factory.
               CreateAlgorithm<SignData>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedDSA(keyPair.PublicKey.Parameters, 32))
                {
                    // выполнить тест
                    SignTest(factory, scope, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags
                    ); 
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), ASN1.Null.Instance
            );
            // указать параметры алгоритма подписи данных
            signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_dsa_sha2_384), null
            );
            // получить алгоритм подписи данных
            using (SignData signAlgorithm = keyPair.PrivateKey.Factory.
               CreateAlgorithm<SignData>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedDSA(keyPair.PublicKey.Parameters, 48))
                {
                    // выполнить тест
                    SignTest(factory, scope, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags
                    ); 
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), ASN1.Null.Instance
            );
            // указать параметры алгоритма подписи данных
            signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_dsa_sha2_512), null
            );
            // получить алгоритм подписи данных
            using (SignData signAlgorithm = keyPair.PrivateKey.Factory.
               CreateAlgorithm<SignData>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedDSA(keyPair.PublicKey.Parameters, 64))
                {
                    // выполнить тест
                    SignTest(factory, scope, hashParameters, 
                        signHashParameters, signParameters, keyPair, keyFlags
                    ); 
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование DH
        ////////////////////////////////////////////////////////////////////////////
        public static void TestDH(CAPI.Factory factory, SecurityObject scope,
            IRand rand, bool generate, KeyFlags keyFlags)
        {
            WriteLine("DH/EPHEMERAL");

            // указать идентификатор ключа
            String keyOID = ASN1.ANSI.OID.x942_dh_public_key; 
        
            // указать доверенную фабрику
            using (CAPI.Factory trustFactory = new ANSI.Factory()) 
            { 
                // получить фабрику кодирования ключа
                KeyFactory keyFactory = trustFactory.GetKeyFactory(keyOID); 
        
                // указать способ использования ключа
                KeyUsage keyUsage = KeyUsage.KeyAgreement; 
        
                // раскодировать параметры алгоритма
                IParameters parameters = keyFactory.DecodeParameters(
                    ASN1.ANSI.X942.DomainParameters.Ephemeral
                ); 
                // сгенерировать ключевую пару
                using (KeyPair keyPair = GenerateKeyPair(
                    factory, scope, rand, trustFactory, null, generate, 
                    keyOID, parameters, keyUsage, keyFlags)) 
                try {
                    // выполнить тест
                    TestDH(trustFactory, null, keyPair, keyFlags); 
                }
                // удалить ключи контейнера
                finally { DeleteKeys(scope); }
            }
            WriteLine();        
        }
        public static void TestDH(CAPI.Factory factory, SecurityStore scope, 
            KeyPair keyPair, KeyFlags keyFlags)
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
                    TestDH(factory, scope, rand, keyPair, keyFlags, ephemeralKeyPair, 
                        ASN1.ISO.PKCS.PKCS9.OID.smime_ssdh, 
                        ASN1.ISO.PKCS.PKCS9.OID.smime_esdh
                    ); 
                }
            }
        }
        private static void TestDH(CAPI.Factory factory, SecurityStore scope,
            IRand rand, KeyPair keyPair, KeyFlags keyFlags, 
            KeyPair ephemeralKeyPair, params String[] algOIDs)
        {
            {
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.smime_rc2_128_wrap),         
                    ASN1.ANSI.RSA.RC2ParameterVersion.GetVersion(128)
                ); 
                // выполнить тест
                TestDH(factory, scope, keyPair, keyFlags, ephemeralKeyPair, algOIDs, wrapParameters, 8); 
            }{
                // сгенерировать ключ и синхропосылку
                byte[] iv = new byte[8]; rand.Generate(iv, 0, iv.Length); 

                // закодировать параметры алгоритма шифрования
                ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_cbc), new ASN1.OctetString(iv)
                ); 
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.smime_pwri_kek),         
                    cipherParameters
                ); 
                // выполнить тест
                TestDH(factory, scope, keyPair, keyFlags, ephemeralKeyPair, algOIDs, wrapParameters, 8); 
            }{
                // сгенерировать ключ и синхропосылку
                byte[] iv = new byte[8]; rand.Generate(iv, 0, iv.Length); 

                // закодировать параметры алгоритма шифрования
                ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_tdes192_cbc), new ASN1.OctetString(iv)
                ); 
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.smime_pwri_kek),         
                    cipherParameters
                ); 
                // выполнить тест
                TestDH(factory, scope, keyPair, keyFlags, ephemeralKeyPair, algOIDs, wrapParameters, 24); 
            }{
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.smime_tdes192_wrap), ASN1.Null.Instance
                ); 
                // выполнить тест
                TestDH(factory, scope, keyPair, keyFlags, ephemeralKeyPair, algOIDs, wrapParameters, 24); 
            }{
                // сгенерировать ключ и синхропосылку
                byte[] iv = new byte[16]; rand.Generate(iv, 0, iv.Length); 

                // закодировать параметры алгоритма шифрования
                ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_cbc), new ASN1.OctetString(iv)
                ); 
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.smime_pwri_kek),         
                    cipherParameters
                ); 
                // выполнить тест
                TestDH(factory, scope, keyPair, keyFlags, ephemeralKeyPair, algOIDs, wrapParameters, 16); 
            }{
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_wrap), ASN1.Null.Instance
                ); 
                // выполнить тест
                TestDH(factory, scope, keyPair, keyFlags, ephemeralKeyPair, algOIDs, wrapParameters, 16); 
            }{
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_wrap_pad), ASN1.Null.Instance
                ); 
                // выполнить тест
                TestDH(factory, scope, keyPair, keyFlags, ephemeralKeyPair, algOIDs, wrapParameters, 16); 
            }{
                // сгенерировать ключ и синхропосылку
                byte[] iv = new byte[16]; rand.Generate(iv, 0, iv.Length); 

                // закодировать параметры алгоритма шифрования
                ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes192_cbc), new ASN1.OctetString(iv)
                ); 
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.smime_pwri_kek),         
                    cipherParameters
                ); 
                // выполнить тест
                TestDH(factory, scope, keyPair, keyFlags, ephemeralKeyPair, algOIDs, wrapParameters, 24); 
            }{
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes192_wrap), ASN1.Null.Instance
                ); 
                // выполнить тест
                TestDH(factory, scope, keyPair, keyFlags, ephemeralKeyPair, algOIDs, wrapParameters, 24); 
            }{
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes192_wrap_pad), ASN1.Null.Instance
                ); 
                // выполнить тест
                TestDH(factory, scope, keyPair, keyFlags, ephemeralKeyPair, algOIDs, wrapParameters, 24); 
            }{
                // сгенерировать ключ и синхропосылку
                byte[] iv = new byte[16]; rand.Generate(iv, 0, iv.Length); 

                // закодировать параметры алгоритма шифрования
                ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_cbc), new ASN1.OctetString(iv)
                ); 
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.smime_pwri_kek),         
                    cipherParameters
                ); 
                // выполнить тест
                TestDH(factory, scope, keyPair, keyFlags, ephemeralKeyPair, algOIDs, wrapParameters, 32); 
            }{
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_wrap), ASN1.Null.Instance
                ); 
                // выполнить тест
                TestDH(factory, scope, keyPair, keyFlags, ephemeralKeyPair, algOIDs, wrapParameters, 32); 
            }{
                // закодировать параметры алгоритма шифрования ключа
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_wrap_pad), ASN1.Null.Instance
                ); 
                // выполнить тест
                TestDH(factory, scope, keyPair, keyFlags, ephemeralKeyPair, algOIDs, wrapParameters, 32); 
            }
        }
        private static void TestDH(CAPI.Factory factory, SecurityStore scope,
            KeyPair keyPair, KeyFlags keyFlags, KeyPair ephemeralKeyPair, String[] algOIDs, 
            ASN1.ISO.AlgorithmIdentifier wrapParameters, int keySize)
        {
            foreach (String algOID in algOIDs)
            {    
                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(algOID), wrapParameters
                ); 
                // получить алгоритм согласования ключа
                using (ITransportAgreement agreement = 
                    keyPair.PrivateKey.Factory.CreateAlgorithm<ITransportAgreement>(
                    keyPair.PrivateKey.Scope, parameters))
                {
                    // при наличии алгоритма
                    if (agreement != null)
                    {
                        // выполнить тест
                        TransportAgreementTest(factory, scope, parameters, 
                            keyPair, keyFlags, ephemeralKeyPair, new int[] {keySize}
                        );
                    }
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование ECDSA/ECDH
        ////////////////////////////////////////////////////////////////////////////
        public static void TestEC(CAPI.Factory factory, SecurityObject scope,
            IRand rand, bool generate, KeyFlags keyFlags, String paramOID)
        {
            WriteLine("EC/{0}", paramOID);
        
            // указать идентификатор ключа
            String keyOID = ASN1.ANSI.OID.x962_ec_public_key; 
        
            // указать доверенную фабрику
            using (CAPI.Factory trustFactory = new ANSI.Factory()) 
            { 
                // получить фабрику кодирования ключа
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
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.DigitalSignature) != KeyUsage.None)
                    { 
                        // выполнить тест
                        TestECDSA(trustFactory, null, keyPair, keyFlags); 
                    }
                    // при допустимости теста
                    if ((keyUsage & KeyUsage.KeyAgreement) != KeyUsage.None)
                    { 
                        // выполнить тест
                        TestECDH(trustFactory, null, keyPair, keyFlags); 
                    }
                }
                // удалить ключи контейнера
                finally { DeleteKeys(scope); }
            }
            WriteLine();
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование ECDSA
        ////////////////////////////////////////////////////////////////////////////
        private static bool HashSupportedECDSA(IParameters parameters, int hashSize) 
        { 
            // преобразовать тип параметров
            X962.IParameters ecParameters = (X962.IParameters)parameters; 

            // проверить размер хэш-значения
            return (hashSize * 8 <= ecParameters.Order.BitLength); 
        }
        public static void TestECDSA(CAPI.Factory factory, Container container) 
        {
            WriteLine("ECDSA");
        
            // закодировать параметры алгоритма хэширования
            ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
            ); 
            // закодировать параметры алгоритма подписи
            ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha1), ASN1.Null.Instance
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
                        Sign.ECDSA.SignHash.Test(factory, container, signHash, hashAlgorithm);
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
                        Sign.ECDSA.VerifyHash.Test(verifyHash, hashAlgorithm);
                    }
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
                        Sign.ECDSA.SignHash.Test(factory, container, signHash, hashAlgorithm);
                    }
                    // вывести сообщение
                    Write("OK  "); 
                
                    // получить алгоритм проверки подписи
                    using (VerifyHash verifyHash = factory.CreateAlgorithm<VerifyHash>(
                        null, signHashParameters))
                    {
                        // выполнить тест
                        Sign.ECDSA.VerifyHash.Test(verifyHash, hashAlgorithm);
                    }
                    // вывести сообщение
                    Write("OK  "); 
                }
            }
            WriteLine();
        }
        public static void TestECDSA(CAPI.Factory factory, 
            SecurityStore scope, KeyPair keyPair, KeyFlags keyFlags)
        {
            // закодировать параметры алгоритма хэширования
            ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
            );
            // указать параметры алгоритма подписи данных
            ASN1.ISO.AlgorithmIdentifier signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha1), null
            );
            // получить алгоритм подписи данных
            using (SignData signAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<SignData>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                if (signAlgorithm != null) SignTest(factory, scope, 
                    hashParameters, signParameters, signParameters, keyPair, keyFlags 
                ); 
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), ASN1.Null.Instance
            );
            // указать параметры алгоритма подписи данных
            signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha2_224), null
            );
            // получить алгоритм подписи данных
            using (SignData signAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<SignData>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedECDSA(keyPair.PublicKey.Parameters, 28)) 
                {
                    // выполнить тест
                    SignTest(factory, scope, hashParameters, 
                        signParameters, signParameters, keyPair, keyFlags
                    ); 
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
            );
            // указать параметры алгоритма подписи данных
            signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha2_256), null
            );
            // получить алгоритм подписи данных
            using (SignData signAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<SignData>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedECDSA(keyPair.PublicKey.Parameters, 32)) 
                {
                    // выполнить тест
                    SignTest(factory, scope, hashParameters, 
                        signParameters, signParameters, keyPair, keyFlags
                    ); 
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), ASN1.Null.Instance
            );
            // указать параметры алгоритма подписи данных
            signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha2_384), null
            );
            // получить алгоритм подписи данных
            using (SignData signAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<SignData>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedECDSA(keyPair.PublicKey.Parameters, 48)) 
                {
                    // выполнить тест
                    SignTest(factory, scope, hashParameters, 
                        signParameters, signParameters, keyPair, keyFlags
                    ); 
                }
            }
            // закодировать параметры алгоритма хэширования
            hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), ASN1.Null.Instance
            );
            // указать параметры алгоритма подписи данных
            signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha2_512), null
            );
            // получить алгоритм подписи данных
            using (SignData signAlgorithm = keyPair.PrivateKey.Factory.
                CreateAlgorithm<SignData>(keyPair.PrivateKey.Scope, signParameters)) 
            {
                // при поддержке алгоритма
                if (signAlgorithm != null && HashSupportedECDSA(keyPair.PublicKey.Parameters, 64)) 
                {
                    // выполнить тест
                    SignTest(factory, scope, hashParameters, 
                        signParameters, signParameters, keyPair, keyFlags
                    ); 
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование ECDH
        ////////////////////////////////////////////////////////////////////////////
        public static void TestECDH(CAPI.Factory factory, SecurityStore scope, 
            KeyPair keyPair, KeyFlags keyFlags)
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
                    TestDH(factory, scope, rand, keyPair, keyFlags, ephemeralKeyPair, 
                        ASN1.ANSI.OID.x963_ecdh_std_sha1, 
                        ASN1.ANSI.OID.certicom_ecdh_std_sha2_256, 
                        ASN1.ANSI.OID.certicom_ecdh_std_sha2_384, 
                        ASN1.ANSI.OID.certicom_ecdh_std_sha2_512, 
                        ASN1.ANSI.OID.x963_ecdh_cofactor_sha1, 
                        ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_256, 
                        ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_384, 
                        ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_512
                    ); 
                }
            }
        }
    }
}

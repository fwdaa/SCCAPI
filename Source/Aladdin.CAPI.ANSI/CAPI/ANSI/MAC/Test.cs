using System;
using System.Text;

namespace Aladdin.CAPI.ANSI.MAC
{
    public static class Test
    {
        ////////////////////////////////////////////////////////////////////////////
        // HMAC-MD5
        ////////////////////////////////////////////////////////////////////////////
        public static void TestHMAC_MD5(
            Factory factory, SecurityStore scope, int[] keySizes)
        {
            // указать идентификатор алгоритма
            ASN1.ObjectIdentifier oid = new ASN1.ObjectIdentifier(
                ASN1.ANSI.OID.ipsec_hmac_md5
            );
            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(oid), ASN1.Null.Instance
            );
            // создать алгоритм 
            using (MAC algorithm = factory.CreateAlgorithm<MAC>(scope, parameters))
            { 
                // указать доверенную фабрику
                using (Factory trustFactory = new Factory())
                { 
                    // выполнить тест
                    CAPI.Test.MAC.Test(algorithm, 
                        trustFactory, null, parameters, keySizes, 0, 65
                    ); 
                }
                if (KeySizes.Contains(algorithm.KeySizes, 16))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
                }, 1, "Hi There", new byte[] {
                    (byte)0x92, (byte)0x94, (byte)0x72, (byte)0x7a, 
                    (byte)0x36, (byte)0x38, (byte)0xbb, (byte)0x1c, 
                    (byte)0x13, (byte)0xf4, (byte)0x8e, (byte)0xf8, 
                    (byte)0x15, (byte)0x8b, (byte)0xfc, (byte)0x9d
                });
                if (KeySizes.Contains(algorithm.KeySizes, 4))
                CAPI.Test.MAC.Test(algorithm, Encoding.UTF8.GetBytes("Jefe"),
                    1, "what do ya want for nothing?", new byte[] {
                    (byte)0x75, (byte)0x0c, (byte)0x78, (byte)0x3e, 
                    (byte)0x6a, (byte)0xb0, (byte)0xb5, (byte)0x03, 
                    (byte)0xea, (byte)0xa8, (byte)0x6e, (byte)0x31, 
                    (byte)0x0a, (byte)0x5d, (byte)0xb7, (byte)0x38
                });
                if (KeySizes.Contains(algorithm.KeySizes, 16))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                }, 50, new byte[] { (byte)0xDD }, new byte[] {
                    (byte)0x56, (byte)0xbe, (byte)0x34, (byte)0x52, 
                    (byte)0x1d, (byte)0x14, (byte)0x4c, (byte)0x88, 
                    (byte)0xdb, (byte)0xb8, (byte)0xc7, (byte)0x33, 
                    (byte)0xf0, (byte)0xe8, (byte)0xb3, (byte)0xf6
                });
                if (KeySizes.Contains(algorithm.KeySizes, 16))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c
                }, 1, "Test With Truncation", new byte[] {
                    (byte)0x56, (byte)0x46, (byte)0x1e, (byte)0xf2, 
                    (byte)0x34, (byte)0x2e, (byte)0xdc, (byte)0x00, 
                    (byte)0xf9, (byte)0xba, (byte)0xb9, (byte)0x95, 
                    (byte)0x69, (byte)0x0e, (byte)0xfd, (byte)0x4c
                });
                if (KeySizes.Contains(algorithm.KeySizes, 80))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                }, 1, "Test Using Larger Than Block-Size Key - Hash Key First", new byte[] {
                    (byte)0x6b, (byte)0x1a, (byte)0xb7, (byte)0xfe, 
                    (byte)0x4b, (byte)0xd7, (byte)0xbf, (byte)0x8f, 
                    (byte)0x0b, (byte)0x62, (byte)0xe6, (byte)0xce, 
                    (byte)0x61, (byte)0xb9, (byte)0xd0, (byte)0xcd        
                });
                if (KeySizes.Contains(algorithm.KeySizes, 80))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                }, 1, "Test Using Larger Than Block-Size Key and Larger " +
                      "Than One Block-Size Data", new byte[] {
                    (byte)0x6f, (byte)0x63, (byte)0x0f, (byte)0xad, 
                    (byte)0x67, (byte)0xcd, (byte)0xa0, (byte)0xee, 
                    (byte)0x1f, (byte)0xb1, (byte)0xf5, (byte)0x62, 
                    (byte)0xdb, (byte)0x3a, (byte)0xa5, (byte)0x3e        
                });
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // HMAC-RIPEMD128
        ////////////////////////////////////////////////////////////////////////////
        public static void TestHMAC_RIPEMD128(
            Factory factory, SecurityStore scope, int[] keySizes)
        {
            // указать идентификатор алгоритма
            ASN1.ObjectIdentifier oid = new ASN1.ObjectIdentifier(
                ASN1.ANSI.OID.tt_ripemd128
            );
            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(oid), ASN1.Null.Instance
            );
            // создать алгоритм
            using (MAC algorithm = CAPI.MAC.HMAC.Create(factory, scope, parameters)) 
            {
                if (KeySizes.Contains(algorithm.KeySizes, 16))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
                }, 1, "Hi There", new byte[] {
                    (byte)0xfb, (byte)0xf6, (byte)0x1f, (byte)0x94, 
                    (byte)0x92, (byte)0xaa, (byte)0x4b, (byte)0xbf, 
                    (byte)0x81, (byte)0xc1, (byte)0x72, (byte)0xe8, 
                    (byte)0x4e, (byte)0x07, (byte)0x34, (byte)0xdb
                });
                if (KeySizes.Contains(algorithm.KeySizes, 4))
                CAPI.Test.MAC.Test(algorithm, Encoding.UTF8.GetBytes("Jefe"),
                    1, "what do ya want for nothing?", new byte[] {
                    (byte)0x87, (byte)0x5f, (byte)0x82, (byte)0x88, 
                    (byte)0x62, (byte)0xb6, (byte)0xb3, (byte)0x34, 
                    (byte)0xb4, (byte)0x27, (byte)0xc5, (byte)0x5f, 
                    (byte)0x9f, (byte)0x7f, (byte)0xf0, (byte)0x9b
                });
                if (KeySizes.Contains(algorithm.KeySizes, 16))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                }, 50, new byte[] { (byte)0xDD }, new byte[] {
                    (byte)0x09, (byte)0xf0, (byte)0xb2, (byte)0x84, 
                    (byte)0x6d, (byte)0x2f, (byte)0x54, (byte)0x3d, 
                    (byte)0xa3, (byte)0x63, (byte)0xcb, (byte)0xec, 
                    (byte)0x8d, (byte)0x62, (byte)0xa3, (byte)0x8d
                });
                if (KeySizes.Contains(algorithm.KeySizes, 24))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                    (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
                    (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, 
                    (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10, 
                    (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, 
                    (byte)0x15, (byte)0x16, (byte)0x17, (byte)0x18, 
                    (byte)0x19
                }, 50, new byte[] { (byte)0xCD }, new byte[] {
                    (byte)0xbd, (byte)0xbb, (byte)0xd7, (byte)0xcf, 
                    (byte)0x03, (byte)0xe4, (byte)0x4b, (byte)0x5a, 
                    (byte)0xa6, (byte)0x0a, (byte)0xf8, (byte)0x15, 
                    (byte)0xbe, (byte)0x4d, (byte)0x22, (byte)0x94
                });
                if (KeySizes.Contains(algorithm.KeySizes, 16))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c
                }, 1, "Test With Truncation", new byte[] {
                    (byte)0xe7, (byte)0x98, (byte)0x08, (byte)0xf2, 
                    (byte)0x4b, (byte)0x25, (byte)0xfd, (byte)0x03, 
                    (byte)0x1c, (byte)0x15, (byte)0x5f, (byte)0x0d, 
                    (byte)0x55, (byte)0x1d, (byte)0x9a, (byte)0x3a
                });
                if (KeySizes.Contains(algorithm.KeySizes, 80))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                }, 1, "Test Using Larger Than Block-Size Key - Hash Key First", new byte[] {
                    (byte)0xdc, (byte)0x73, (byte)0x29, (byte)0x28, 
                    (byte)0xde, (byte)0x98, (byte)0x10, (byte)0x4a, 
                    (byte)0x1f, (byte)0x59, (byte)0xd3, (byte)0x73, 
                    (byte)0xc1, (byte)0x50, (byte)0xac, (byte)0xbb
                });
                if (KeySizes.Contains(algorithm.KeySizes, 80))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                }, 1, "Test Using Larger Than Block-Size Key and Larger " +
                      "Than One Block-Size Data", new byte[] {
                    (byte)0x5c, (byte)0x6b, (byte)0xec, (byte)0x96, 
                    (byte)0x79, (byte)0x3e, (byte)0x16, (byte)0xd4, 
                    (byte)0x06, (byte)0x90, (byte)0xc2, (byte)0x37, 
                    (byte)0x63, (byte)0x5f, (byte)0x30, (byte)0xc5
                });
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // HMAC-RIPEMD160
        ////////////////////////////////////////////////////////////////////////////
        public static void TestHMAC_RIPEMD160(
            Factory factory, SecurityStore scope, int[] keySizes)
        {
            // указать идентификатор алгоритма
            ASN1.ObjectIdentifier oid = new ASN1.ObjectIdentifier(
                ASN1.ANSI.OID.ipsec_hmac_ripemd160
            );
            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(oid), ASN1.Null.Instance
            );
            // создать алгоритм хэширования
            using (MAC algorithm = factory.CreateAlgorithm<MAC>(scope, parameters))
            { 
                // указать доверенную фабрику
                using (Factory trustFactory = new Factory())
                { 
                    // выполнить тест
                    CAPI.Test.MAC.Test(algorithm, 
                        trustFactory, null, parameters, keySizes, 0, 65
                    ); 
                }
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
                }, 1, "Hi There", new byte[] {
                    (byte)0x24, (byte)0xcb, (byte)0x4b, (byte)0xd6, 
                    (byte)0x7d, (byte)0x20, (byte)0xfc, (byte)0x1a, 
                    (byte)0x5d, (byte)0x2e, (byte)0xd7, (byte)0x73, 
                    (byte)0x2d, (byte)0xcc, (byte)0x39, (byte)0x37, 
                    (byte)0x7f, (byte)0x0a, (byte)0x56, (byte)0x68
                });
                if (KeySizes.Contains(algorithm.KeySizes, 4))
                CAPI.Test.MAC.Test(algorithm, Encoding.UTF8.GetBytes("Jefe"),
                    1, "what do ya want for nothing?", new byte[] {
                    (byte)0xdd, (byte)0xa6, (byte)0xc0, (byte)0x21, 
                    (byte)0x3a, (byte)0x48, (byte)0x5a, (byte)0x9e, 
                    (byte)0x24, (byte)0xf4, (byte)0x74, (byte)0x20, 
                    (byte)0x64, (byte)0xa7, (byte)0xf0, (byte)0x33, 
                    (byte)0xb4, (byte)0x3c, (byte)0x40, (byte)0x69
                    });
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA 
                }, 50, new byte[] { (byte)0xDD }, new byte[] {
                    (byte)0xb0, (byte)0xb1, (byte)0x05, (byte)0x36, 
                    (byte)0x0d, (byte)0xe7, (byte)0x59, (byte)0x96, 
                    (byte)0x0a, (byte)0xb4, (byte)0xf3, (byte)0x52, 
                    (byte)0x98, (byte)0xe1, (byte)0x16, (byte)0xe2, 
                    (byte)0x95, (byte)0xd8, (byte)0xe7, (byte)0xc1
                });
                if (KeySizes.Contains(algorithm.KeySizes, 24))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                    (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
                    (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, 
                    (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10, 
                    (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, 
                    (byte)0x15, (byte)0x16, (byte)0x17, (byte)0x18, 
                    (byte)0x19
                }, 50, new byte[] { (byte)0xCD }, new byte[] {
                    (byte)0xd5, (byte)0xca, (byte)0x86, (byte)0x2f, 
                    (byte)0x4d, (byte)0x21, (byte)0xd5, (byte)0xe6, 
                    (byte)0x10, (byte)0xe1, (byte)0x8b, (byte)0x4c, 
                    (byte)0xf1, (byte)0xbe, (byte)0xb9, (byte)0x7a, 
                    (byte)0x43, (byte)0x65, (byte)0xec, (byte)0xf4        
                });
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c,
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c
                }, 1, "Test With Truncation", new byte[] {
                    (byte)0x76, (byte)0x19, (byte)0x69, (byte)0x39, 
                    (byte)0x78, (byte)0xf9, (byte)0x1d, (byte)0x90, 
                    (byte)0x53, (byte)0x9a, (byte)0xe7, (byte)0x86, 
                    (byte)0x50, (byte)0x0f, (byte)0xf3, (byte)0xd8, 
                    (byte)0xe0, (byte)0x51, (byte)0x8e, (byte)0x39        
                });
                if (KeySizes.Contains(algorithm.KeySizes, 80))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                }, 1, "Test Using Larger Than Block-Size Key - Hash Key First", new byte[] {
                    (byte)0x64, (byte)0x66, (byte)0xca, (byte)0x07, 
                    (byte)0xac, (byte)0x5e, (byte)0xac, (byte)0x29, 
                    (byte)0xe1, (byte)0xbd, (byte)0x52, (byte)0x3e, 
                    (byte)0x5a, (byte)0xda, (byte)0x76, (byte)0x05, 
                    (byte)0xb7, (byte)0x91, (byte)0xfd, (byte)0x8b        
                });
                if (KeySizes.Contains(algorithm.KeySizes, 80))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                }, 1, "Test Using Larger Than Block-Size Key and Larger " +
                      "Than One Block-Size Data", new byte[] {
                    (byte)0x69, (byte)0xea, (byte)0x60, (byte)0x79, 
                    (byte)0x8d, (byte)0x71, (byte)0x61, (byte)0x6c, 
                    (byte)0xce, (byte)0x5f, (byte)0xd0, (byte)0x87, 
                    (byte)0x1e, (byte)0x23, (byte)0x75, (byte)0x4c, 
                    (byte)0xd7, (byte)0x5d, (byte)0x5a, (byte)0x0a
                });
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // HMAC-SHA1
        ////////////////////////////////////////////////////////////////////////////
        public static void TestHMAC_SHA1(
            Factory factory, SecurityStore scope, int[] keySizes)
        {
            // указать идентификатор алгоритма
            ASN1.ObjectIdentifier oid = new ASN1.ObjectIdentifier(
                ASN1.ANSI.OID.rsa_hmac_sha1
            );
            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(oid), ASN1.Null.Instance
            );
            // создать алгоритм 
            using (MAC algorithm = factory.CreateAlgorithm<MAC>(scope, parameters))
            { 
                // указать доверенную фабрику
                using (Factory trustFactory = new Factory())
                { 
                    // выполнить тест
                    CAPI.Test.MAC.Test(algorithm, 
                        trustFactory, null, parameters, keySizes, 0, 65
                    ); 
                }
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
                }, 1, "Hi There", new byte[] {
                    (byte)0xb6, (byte)0x17, (byte)0x31, (byte)0x86, 
                    (byte)0x55, (byte)0x05, (byte)0x72, (byte)0x64, 
                    (byte)0xe2, (byte)0x8b, (byte)0xc0, (byte)0xb6, 
                    (byte)0xfb, (byte)0x37, (byte)0x8c, (byte)0x8e, 
                    (byte)0xf1, (byte)0x46, (byte)0xbe, (byte)0x00        
                });
                if (KeySizes.Contains(algorithm.KeySizes, 4))
                CAPI.Test.MAC.Test(algorithm, Encoding.UTF8.GetBytes("Jefe"),
                    1, "what do ya want for nothing?", new byte[] {
                    (byte)0xef, (byte)0xfc, (byte)0xdf, (byte)0x6a, 
                    (byte)0xe5, (byte)0xeb, (byte)0x2f, (byte)0xa2, 
                    (byte)0xd2, (byte)0x74, (byte)0x16, (byte)0xd5, 
                    (byte)0xf1, (byte)0x84, (byte)0xdf, (byte)0x9c, 
                    (byte)0x25, (byte)0x9a, (byte)0x7c, (byte)0x79            
                });
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA 
                }, 50, new byte[] { (byte)0xDD }, new byte[] {
                    (byte)0x12, (byte)0x5d, (byte)0x73, (byte)0x42, 
                    (byte)0xb9, (byte)0xac, (byte)0x11, (byte)0xcd, 
                    (byte)0x91, (byte)0xa3, (byte)0x9a, (byte)0xf4, 
                    (byte)0x8a, (byte)0xa1, (byte)0x7b, (byte)0x4f, 
                    (byte)0x63, (byte)0xf1, (byte)0x75, (byte)0xd3        
                });
                if (KeySizes.Contains(algorithm.KeySizes, 24))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                    (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
                    (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, 
                    (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10, 
                    (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, 
                    (byte)0x15, (byte)0x16, (byte)0x17, (byte)0x18, 
                    (byte)0x19
                }, 50, new byte[] { (byte)0xCD }, new byte[] {
                    (byte)0x4c, (byte)0x90, (byte)0x07, (byte)0xf4, 
                    (byte)0x02, (byte)0x62, (byte)0x50, (byte)0xc6, 
                    (byte)0xbc, (byte)0x84, (byte)0x14, (byte)0xf9, 
                    (byte)0xbf, (byte)0x50, (byte)0xc8, (byte)0x6c, 
                    (byte)0x2d, (byte)0x72, (byte)0x35, (byte)0xda        
                });
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c,
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c
                }, 1, "Test With Truncation", new byte[] {
                    (byte)0x4c, (byte)0x1a, (byte)0x03, (byte)0x42, 
                    (byte)0x4b, (byte)0x55, (byte)0xe0, (byte)0x7f, 
                    (byte)0xe7, (byte)0xf2, (byte)0x7b, (byte)0xe1, 
                    (byte)0xd5, (byte)0x8b, (byte)0xb9, (byte)0x32, 
                    (byte)0x4a, (byte)0x9a, (byte)0x5a, (byte)0x04        
                });
                if (KeySizes.Contains(algorithm.KeySizes, 80))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                }, 1, "Test Using Larger Than Block-Size Key - Hash Key First", new byte[] {
                    (byte)0xaa, (byte)0x4a, (byte)0xe5, (byte)0xe1, 
                    (byte)0x52, (byte)0x72, (byte)0xd0, (byte)0x0e, 
                    (byte)0x95, (byte)0x70, (byte)0x56, (byte)0x37, 
                    (byte)0xce, (byte)0x8a, (byte)0x3b, (byte)0x55, 
                    (byte)0xed, (byte)0x40, (byte)0x21, (byte)0x12        
                });
                if (KeySizes.Contains(algorithm.KeySizes, 80))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                }, 1, "Test Using Larger Than Block-Size Key and Larger " +
                      "Than One Block-Size Data", new byte[] {
                    (byte)0xe8, (byte)0xe9, (byte)0x9d, (byte)0x0f, 
                    (byte)0x45, (byte)0x23, (byte)0x7d, (byte)0x78, 
                    (byte)0x6d, (byte)0x6b, (byte)0xba, (byte)0xa7, 
                    (byte)0x96, (byte)0x5c, (byte)0x78, (byte)0x08, 
                    (byte)0xbb, (byte)0xff, (byte)0x1a, (byte)0x91
                });
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // HMAC-SHA2-224
        ////////////////////////////////////////////////////////////////////////////
        public static void TestHMAC_SHA2_224(
            Factory factory, SecurityStore scope, int[] keySizes)
        {
            // указать идентификатор алгоритма
            ASN1.ObjectIdentifier oid = new ASN1.ObjectIdentifier(
                ASN1.ANSI.OID.rsa_hmac_sha2_224
            );
            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(oid), ASN1.Null.Instance
            );
            // создать алгоритм 
            using (MAC algorithm = factory.CreateAlgorithm<MAC>(scope, parameters))
            { 
                // указать доверенную фабрику
                using (Factory trustFactory = new Factory())
                { 
                    // выполнить тест
                    CAPI.Test.MAC.Test(algorithm, 
                        trustFactory, null, parameters, keySizes, 0, 65
                    ); 
                }
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
                }, 1, "Hi There", new byte[] {
                    (byte)0x89, (byte)0x6f, (byte)0xb1, (byte)0x12, 
                    (byte)0x8a, (byte)0xbb, (byte)0xdf, (byte)0x19, 
                    (byte)0x68, (byte)0x32, (byte)0x10, (byte)0x7c, 
                    (byte)0xd4, (byte)0x9d, (byte)0xf3, (byte)0x3f,
                    (byte)0x47, (byte)0xb4, (byte)0xb1, (byte)0x16, 
                    (byte)0x99, (byte)0x12, (byte)0xba, (byte)0x4f, 
                    (byte)0x53, (byte)0x68, (byte)0x4b, (byte)0x22
                });
                if (KeySizes.Contains(algorithm.KeySizes, 4))
                CAPI.Test.MAC.Test(algorithm, Encoding.UTF8.GetBytes("Jefe"),
                    1, "what do ya want for nothing?", new byte[] {
                    (byte)0xa3, (byte)0x0e, (byte)0x01, (byte)0x09, 
                    (byte)0x8b, (byte)0xc6, (byte)0xdb, (byte)0xbf, 
                    (byte)0x45, (byte)0x69, (byte)0x0f, (byte)0x3a, 
                    (byte)0x7e, (byte)0x9e, (byte)0x6d, (byte)0x0f, 
                    (byte)0x8b, (byte)0xbe, (byte)0xa2, (byte)0xa3, 
                    (byte)0x9e, (byte)0x61, (byte)0x48, (byte)0x00, 
                    (byte)0x8f, (byte)0xd0, (byte)0x5e, (byte)0x44        
                });
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA 
                }, 50, new byte[] { (byte)0xDD }, new byte[] {
                    (byte)0x7f, (byte)0xb3, (byte)0xcb, (byte)0x35, 
                    (byte)0x88, (byte)0xc6, (byte)0xc1, (byte)0xf6, 
                    (byte)0xff, (byte)0xa9, (byte)0x69, (byte)0x4d, 
                    (byte)0x7d, (byte)0x6a, (byte)0xd2, (byte)0x64,
                    (byte)0x93, (byte)0x65, (byte)0xb0, (byte)0xc1, 
                    (byte)0xf6, (byte)0x5d, (byte)0x69, (byte)0xd1, 
                    (byte)0xec, (byte)0x83, (byte)0x33, (byte)0xea          
                });
                if (KeySizes.Contains(algorithm.KeySizes, 24))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                    (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
                    (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, 
                    (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10, 
                    (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, 
                    (byte)0x15, (byte)0x16, (byte)0x17, (byte)0x18, 
                    (byte)0x19
                }, 50, new byte[] { (byte)0xCD }, new byte[] {
                    (byte)0x6c, (byte)0x11, (byte)0x50, (byte)0x68, 
                    (byte)0x74, (byte)0x01, (byte)0x3c, (byte)0xac, 
                    (byte)0x6a, (byte)0x2a, (byte)0xbc, (byte)0x1b, 
                    (byte)0xb3, (byte)0x82, (byte)0x62, (byte)0x7c, 
                    (byte)0xec, (byte)0x6a, (byte)0x90, (byte)0xd8, 
                    (byte)0x6e, (byte)0xfc, (byte)0x01, (byte)0x2d, 
                    (byte)0xe7, (byte)0xaf, (byte)0xec, (byte)0x5a
                });
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c,
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c
                }, 1, "Test With Truncation", new byte[] {
                    (byte)0x0e, (byte)0x2a, (byte)0xea, (byte)0x68, 
                    (byte)0xa9, (byte)0x0c, (byte)0x8d, (byte)0x37, 
                    (byte)0xc9, (byte)0x88, (byte)0xbc, (byte)0xdb, 
                    (byte)0x9f, (byte)0xca, (byte)0x6f, (byte)0xa8        
                });
                if (KeySizes.Contains(algorithm.KeySizes, 80))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa
                }, 1, "Test Using Larger Than Block-Size Key - Hash Key First", new byte[] {
                    (byte)0x95, (byte)0xe9, (byte)0xa0, (byte)0xdb, 
                    (byte)0x96, (byte)0x20, (byte)0x95, (byte)0xad, 
                    (byte)0xae, (byte)0xbe, (byte)0x9b, (byte)0x2d, 
                    (byte)0x6f, (byte)0x0d, (byte)0xbc, (byte)0xe2, 
                    (byte)0xd4, (byte)0x99, (byte)0xf1, (byte)0x12, 
                    (byte)0xf2, (byte)0xd2, (byte)0xb7, (byte)0x27, 
                    (byte)0x3f, (byte)0xa6, (byte)0x87, (byte)0x0e
                });
                if (KeySizes.Contains(algorithm.KeySizes, 80))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa
                }, 1, "This is a test using a larger than block-size key and " +
                      "a larger than block-size data. The key needs to be hashed " +
                      "before being used by the HMAC algorithm.", new byte[] {
                    (byte)0x3a, (byte)0x85, (byte)0x41, (byte)0x66, 
                    (byte)0xac, (byte)0x5d, (byte)0x9f, (byte)0x02, 
                    (byte)0x3f, (byte)0x54, (byte)0xd5, (byte)0x17, 
                    (byte)0xd0, (byte)0xb3, (byte)0x9d, (byte)0xbd, 
                    (byte)0x94, (byte)0x67, (byte)0x70, (byte)0xdb, 
                    (byte)0x9c, (byte)0x2b, (byte)0x95, (byte)0xc9, 
                    (byte)0xf6, (byte)0xf5, (byte)0x65, (byte)0xd1
                });
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // HMAC-SHA2-256
        ////////////////////////////////////////////////////////////////////////////
        public static void TestHMAC_SHA2_256(
            Factory factory, SecurityStore scope, int[] keySizes)
        {
            // указать идентификатор алгоритма
            ASN1.ObjectIdentifier oid = new ASN1.ObjectIdentifier(
                ASN1.ANSI.OID.rsa_hmac_sha2_256
            );
            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(oid), ASN1.Null.Instance
            );
            // создать алгоритм 
            using (MAC algorithm = factory.CreateAlgorithm<MAC>(scope, parameters))
            { 
                // указать доверенную фабрику
                using (Factory trustFactory = new Factory())
                { 
                    // выполнить тест
                    CAPI.Test.MAC.Test(algorithm, 
                        trustFactory, null, parameters, keySizes, 0, 65
                    ); 
                }
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
                }, 1, "Hi There", new byte[] {
                    (byte)0xb0, (byte)0x34, (byte)0x4c, (byte)0x61, 
                    (byte)0xd8, (byte)0xdb, (byte)0x38, (byte)0x53, 
                    (byte)0x5c, (byte)0xa8, (byte)0xaf, (byte)0xce, 
                    (byte)0xaf, (byte)0x0b, (byte)0xf1, (byte)0x2b, 
                    (byte)0x88, (byte)0x1d, (byte)0xc2, (byte)0x00, 
                    (byte)0xc9, (byte)0x83, (byte)0x3d, (byte)0xa7, 
                    (byte)0x26, (byte)0xe9, (byte)0x37, (byte)0x6c, 
                    (byte)0x2e, (byte)0x32, (byte)0xcf, (byte)0xf7
                });
                if (KeySizes.Contains(algorithm.KeySizes, 4))
                CAPI.Test.MAC.Test(algorithm, Encoding.UTF8.GetBytes("Jefe"),
                    1, "what do ya want for nothing?", new byte[] {
                    (byte)0x5b, (byte)0xdc, (byte)0xc1, (byte)0x46, 
                    (byte)0xbf, (byte)0x60, (byte)0x75, (byte)0x4e, 
                    (byte)0x6a, (byte)0x04, (byte)0x24, (byte)0x26, 
                    (byte)0x08, (byte)0x95, (byte)0x75, (byte)0xc7, 
                    (byte)0x5a, (byte)0x00, (byte)0x3f, (byte)0x08, 
                    (byte)0x9d, (byte)0x27, (byte)0x39, (byte)0x83, 
                    (byte)0x9d, (byte)0xec, (byte)0x58, (byte)0xb9, 
                    (byte)0x64, (byte)0xec, (byte)0x38, (byte)0x43
                });
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA 
                }, 50, new byte[] { (byte)0xDD }, new byte[] {
			        (byte)0x77, (byte)0x3e, (byte)0xa9, (byte)0x1e, 
			        (byte)0x36, (byte)0x80, (byte)0x0e, (byte)0x46, 
			        (byte)0x85, (byte)0x4d, (byte)0xb8, (byte)0xeb, 
			        (byte)0xd0, (byte)0x91, (byte)0x81, (byte)0xa7, 
			        (byte)0x29, (byte)0x59, (byte)0x09, (byte)0x8b, 
			        (byte)0x3e, (byte)0xf8, (byte)0xc1, (byte)0x22, 
			        (byte)0xd9, (byte)0x63, (byte)0x55, (byte)0x14, 
			        (byte)0xce, (byte)0xd5, (byte)0x65, (byte)0xfe
                });
                if (KeySizes.Contains(algorithm.KeySizes, 24))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                    (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
                    (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, 
                    (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10, 
                    (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, 
                    (byte)0x15, (byte)0x16, (byte)0x17, (byte)0x18, 
                    (byte)0x19
                }, 50, new byte[] { (byte)0xCD }, new byte[] {
			        (byte)0x82, (byte)0x55, (byte)0x8a, (byte)0x38, 
			        (byte)0x9a, (byte)0x44, (byte)0x3c, (byte)0x0e, 
			        (byte)0xa4, (byte)0xcc, (byte)0x81, (byte)0x98, 
			        (byte)0x99, (byte)0xf2, (byte)0x08, (byte)0x3a, 
			        (byte)0x85, (byte)0xf0, (byte)0xfa, (byte)0xa3, 
			        (byte)0xe5, (byte)0x78, (byte)0xf8, (byte)0x07, 
			        (byte)0x7a, (byte)0x2e, (byte)0x3f, (byte)0xf4, 
			        (byte)0x67, (byte)0x29, (byte)0x66, (byte)0x5b
                });
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c,
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c
                }, 1, "Test With Truncation", new byte[] {
			        (byte)0xa3, (byte)0xb6, (byte)0x16, (byte)0x74, 
			        (byte)0x73, (byte)0x10, (byte)0x0e, (byte)0xe0, 
			        (byte)0x6e, (byte)0x0c, (byte)0x79, (byte)0x6c, 
			        (byte)0x29, (byte)0x55, (byte)0x55, (byte)0x2b
                });
                if (KeySizes.Contains(algorithm.KeySizes, 80))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa
                }, 1, "Test Using Larger Than Block-Size Key - Hash Key First", new byte[] {
			        (byte)0x60, (byte)0xe4, (byte)0x31, (byte)0x59, 
			        (byte)0x1e, (byte)0xe0, (byte)0xb6, (byte)0x7f, 
			        (byte)0x0d, (byte)0x8a, (byte)0x26, (byte)0xaa, 
			        (byte)0xcb, (byte)0xf5, (byte)0xb7, (byte)0x7f, 
			        (byte)0x8e, (byte)0x0b, (byte)0xc6, (byte)0x21, 
			        (byte)0x37, (byte)0x28, (byte)0xc5, (byte)0x14, 
			        (byte)0x05, (byte)0x46, (byte)0x04, (byte)0x0f, 
			        (byte)0x0e, (byte)0xe3, (byte)0x7f, (byte)0x54
                });
                if (KeySizes.Contains(algorithm.KeySizes, 80))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa
                }, 1, "This is a test using a larger than block-size key and " +
                      "a larger than block-size data. The key needs to be hashed " +
                      "before being used by the HMAC algorithm.", new byte[] {
			        (byte)0x9b, (byte)0x09, (byte)0xff, (byte)0xa7, 
			        (byte)0x1b, (byte)0x94, (byte)0x2f, (byte)0xcb, 
			        (byte)0x27, (byte)0x63, (byte)0x5f, (byte)0xbc, 
			        (byte)0xd5, (byte)0xb0, (byte)0xe9, (byte)0x44,
			        (byte)0xbf, (byte)0xdc, (byte)0x63, (byte)0x64, 
			        (byte)0x4f, (byte)0x07, (byte)0x13, (byte)0x93, 
			        (byte)0x8a, (byte)0x7f, (byte)0x51, (byte)0x53, 
			        (byte)0x5c, (byte)0x3a, (byte)0x35, (byte)0xe2
                });
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // HMAC-SHA2-384
        ////////////////////////////////////////////////////////////////////////////
        public static void TestHMAC_SHA2_384(
            Factory factory, SecurityStore scope, int[] keySizes)
        {
            // указать идентификатор алгоритма
            ASN1.ObjectIdentifier oid = new ASN1.ObjectIdentifier(
                ASN1.ANSI.OID.rsa_hmac_sha2_384
            );
            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(oid), ASN1.Null.Instance
            );
            // создать алгоритм 
            using (MAC algorithm = factory.CreateAlgorithm<MAC>(scope, parameters))
            { 
                // указать доверенную фабрику
                using (Factory trustFactory = new Factory())
                { 
                    // выполнить тест
                    CAPI.Test.MAC.Test(algorithm, 
                        trustFactory, null, parameters, keySizes, 0, 129
                    ); 
                }
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
                }, 1, "Hi There", new byte[] {
			        (byte)0xaf, (byte)0xd0, (byte)0x39, (byte)0x44, 
			        (byte)0xd8, (byte)0x48, (byte)0x95, (byte)0x62, 
			        (byte)0x6b, (byte)0x08, (byte)0x25, (byte)0xf4, 
			        (byte)0xab, (byte)0x46, (byte)0x90, (byte)0x7f, 
			        (byte)0x15, (byte)0xf9, (byte)0xda, (byte)0xdb, 
			        (byte)0xe4, (byte)0x10, (byte)0x1e, (byte)0xc6, 
			        (byte)0x82, (byte)0xaa, (byte)0x03, (byte)0x4c, 
			        (byte)0x7c, (byte)0xeb, (byte)0xc5, (byte)0x9c, 
			        (byte)0xfa, (byte)0xea, (byte)0x9e, (byte)0xa9, 
			        (byte)0x07, (byte)0x6e, (byte)0xde, (byte)0x7f, 
			        (byte)0x4a, (byte)0xf1, (byte)0x52, (byte)0xe8, 
			        (byte)0xb2, (byte)0xfa, (byte)0x9c, (byte)0xb6
                });
                if (KeySizes.Contains(algorithm.KeySizes, 4))
                CAPI.Test.MAC.Test(algorithm, Encoding.UTF8.GetBytes("Jefe"),
                    1, "what do ya want for nothing?", new byte[] {
			        (byte)0xaf, (byte)0x45, (byte)0xd2, (byte)0xe3, 
			        (byte)0x76, (byte)0x48, (byte)0x40, (byte)0x31, 
			        (byte)0x61, (byte)0x7f, (byte)0x78, (byte)0xd2, 
			        (byte)0xb5, (byte)0x8a, (byte)0x6b, (byte)0x1b, 
			        (byte)0x9c, (byte)0x7e, (byte)0xf4, (byte)0x64, 
			        (byte)0xf5, (byte)0xa0, (byte)0x1b, (byte)0x47, 
			        (byte)0xe4, (byte)0x2e, (byte)0xc3, (byte)0x73, 
			        (byte)0x63, (byte)0x22, (byte)0x44, (byte)0x5e, 
			        (byte)0x8e, (byte)0x22, (byte)0x40, (byte)0xca, 
			        (byte)0x5e, (byte)0x69, (byte)0xe2, (byte)0xc7, 
			        (byte)0x8b, (byte)0x32, (byte)0x39, (byte)0xec, 
			        (byte)0xfa, (byte)0xb2, (byte)0x16, (byte)0x49
                });
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA 
                }, 50, new byte[] { (byte)0xDD }, new byte[] {
			        (byte)0x88, (byte)0x06, (byte)0x26, (byte)0x08, 
			        (byte)0xd3, (byte)0xe6, (byte)0xad, (byte)0x8a, 
			        (byte)0x0a, (byte)0xa2, (byte)0xac, (byte)0xe0, 
			        (byte)0x14, (byte)0xc8, (byte)0xa8, (byte)0x6f, 
			        (byte)0x0a, (byte)0xa6, (byte)0x35, (byte)0xd9, 
			        (byte)0x47, (byte)0xac, (byte)0x9f, (byte)0xeb, 
			        (byte)0xe8, (byte)0x3e, (byte)0xf4, (byte)0xe5, 
			        (byte)0x59, (byte)0x66, (byte)0x14, (byte)0x4b, 
			        (byte)0x2a, (byte)0x5a, (byte)0xb3, (byte)0x9d, 
			        (byte)0xc1, (byte)0x38, (byte)0x14, (byte)0xb9, 
			        (byte)0x4e, (byte)0x3a, (byte)0xb6, (byte)0xe1, 
			        (byte)0x01, (byte)0xa3, (byte)0x4f, (byte)0x27
                });
                if (KeySizes.Contains(algorithm.KeySizes, 24))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                    (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
                    (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, 
                    (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10, 
                    (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, 
                    (byte)0x15, (byte)0x16, (byte)0x17, (byte)0x18, 
                    (byte)0x19
                }, 50, new byte[] { (byte)0xCD }, new byte[] {
			        (byte)0x3e, (byte)0x8a, (byte)0x69, (byte)0xb7, 
			        (byte)0x78, (byte)0x3c, (byte)0x25, (byte)0x85, 
			        (byte)0x19, (byte)0x33, (byte)0xab, (byte)0x62, 
			        (byte)0x90, (byte)0xaf, (byte)0x6c, (byte)0xa7, 
			        (byte)0x7a, (byte)0x99, (byte)0x81, (byte)0x48, 
			        (byte)0x08, (byte)0x50, (byte)0x00, (byte)0x9c, 
			        (byte)0xc5, (byte)0x57, (byte)0x7c, (byte)0x6e, 
			        (byte)0x1f, (byte)0x57, (byte)0x3b, (byte)0x4e, 
			        (byte)0x68, (byte)0x01, (byte)0xdd, (byte)0x23, 
			        (byte)0xc4, (byte)0xa7, (byte)0xd6, (byte)0x79, 
			        (byte)0xcc, (byte)0xf8, (byte)0xa3, (byte)0x86, 
			        (byte)0xc6, (byte)0x74, (byte)0xcf, (byte)0xfb
                });
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c,
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c
                }, 1, "Test With Truncation", new byte[] {
			        (byte)0x3a, (byte)0xbf, (byte)0x34, (byte)0xc3, 
			        (byte)0x50, (byte)0x3b, (byte)0x2a, (byte)0x23, 
			        (byte)0xa4, (byte)0x6e, (byte)0xfc, (byte)0x61, 
			        (byte)0x9b, (byte)0xae, (byte)0xf8, (byte)0x97
                });
                if (KeySizes.Contains(algorithm.KeySizes, 80))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa
                }, 1, "Test Using Larger Than Block-Size Key - Hash Key First", new byte[] {
			        (byte)0x4e, (byte)0xce, (byte)0x08, (byte)0x44, 
			        (byte)0x85, (byte)0x81, (byte)0x3e, (byte)0x90, 
			        (byte)0x88, (byte)0xd2, (byte)0xc6, (byte)0x3a, 
			        (byte)0x04, (byte)0x1b, (byte)0xc5, (byte)0xb4, 
			        (byte)0x4f, (byte)0x9e, (byte)0xf1, (byte)0x01, 
			        (byte)0x2a, (byte)0x2b, (byte)0x58, (byte)0x8f, 
			        (byte)0x3c, (byte)0xd1, (byte)0x1f, (byte)0x05, 
			        (byte)0x03, (byte)0x3a, (byte)0xc4, (byte)0xc6,
			        (byte)0x0c, (byte)0x2e, (byte)0xf6, (byte)0xab, 
			        (byte)0x40, (byte)0x30, (byte)0xfe, (byte)0x82, 
			        (byte)0x96, (byte)0x24, (byte)0x8d, (byte)0xf1, 
			        (byte)0x63, (byte)0xf4, (byte)0x49, (byte)0x52
                });
                if (KeySizes.Contains(algorithm.KeySizes, 80))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa
                }, 1, "This is a test using a larger than block-size key and " +
                      "a larger than block-size data. The key needs to be hashed " +
                      "before being used by the HMAC algorithm.", new byte[] {
			        (byte)0x66, (byte)0x17, (byte)0x17, (byte)0x8e, 
			        (byte)0x94, (byte)0x1f, (byte)0x02, (byte)0x0d, 
			        (byte)0x35, (byte)0x1e, (byte)0x2f, (byte)0x25, 
			        (byte)0x4e, (byte)0x8f, (byte)0xd3, (byte)0x2c, 
			        (byte)0x60, (byte)0x24, (byte)0x20, (byte)0xfe, 
			        (byte)0xb0, (byte)0xb8, (byte)0xfb, (byte)0x9a, 
			        (byte)0xdc, (byte)0xce, (byte)0xbb, (byte)0x82, 
			        (byte)0x46, (byte)0x1e, (byte)0x99, (byte)0xc5,
			        (byte)0xa6, (byte)0x78, (byte)0xcc, (byte)0x31, 
			        (byte)0xe7, (byte)0x99, (byte)0x17, (byte)0x6d, 
			        (byte)0x38, (byte)0x60, (byte)0xe6, (byte)0x11, 
			        (byte)0x0c, (byte)0x46, (byte)0x52, (byte)0x3e
                });
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // HMAC-SHA2-512
        ////////////////////////////////////////////////////////////////////////////
        public static void TestHMAC_SHA2_512(
            Factory factory, SecurityStore scope, int[] keySizes)
        {
            // указать идентификатор алгоритма
            ASN1.ObjectIdentifier oid = new ASN1.ObjectIdentifier(
                ASN1.ANSI.OID.rsa_hmac_sha2_512
            );
            // указать параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier parameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(oid), ASN1.Null.Instance
            );
            // создать алгоритм 
            using (MAC algorithm = factory.CreateAlgorithm<MAC>(scope, parameters))
            { 
                // указать доверенную фабрику
                using (Factory trustFactory = new Factory())
                { 
                    // выполнить тест
                    CAPI.Test.MAC.Test(algorithm, 
                        trustFactory, null, parameters, keySizes, 0, 129
                    ); 
                }
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b, 
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                    (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
                }, 1, "Hi There", new byte[] {
			        (byte)0x87, (byte)0xaa, (byte)0x7c, (byte)0xde, 
			        (byte)0xa5, (byte)0xef, (byte)0x61, (byte)0x9d, 
			        (byte)0x4f, (byte)0xf0, (byte)0xb4, (byte)0x24, 
			        (byte)0x1a, (byte)0x1d, (byte)0x6c, (byte)0xb0, 
			        (byte)0x23, (byte)0x79, (byte)0xf4, (byte)0xe2, 
			        (byte)0xce, (byte)0x4e, (byte)0xc2, (byte)0x78, 
			        (byte)0x7a, (byte)0xd0, (byte)0xb3, (byte)0x05, 
			        (byte)0x45, (byte)0xe1, (byte)0x7c, (byte)0xde, 
			        (byte)0xda, (byte)0xa8, (byte)0x33, (byte)0xb7, 
			        (byte)0xd6, (byte)0xb8, (byte)0xa7, (byte)0x02, 
			        (byte)0x03, (byte)0x8b, (byte)0x27, (byte)0x4e, 
			        (byte)0xae, (byte)0xa3, (byte)0xf4, (byte)0xe4, 
			        (byte)0xbe, (byte)0x9d, (byte)0x91, (byte)0x4e, 
			        (byte)0xeb, (byte)0x61, (byte)0xf1, (byte)0x70, 
			        (byte)0x2e, (byte)0x69, (byte)0x6c, (byte)0x20, 
			        (byte)0x3a, (byte)0x12, (byte)0x68, (byte)0x54
                });
                if (KeySizes.Contains(algorithm.KeySizes, 4))
                CAPI.Test.MAC.Test(algorithm, Encoding.UTF8.GetBytes("Jefe"),
                    1, "what do ya want for nothing?", new byte[] {
			        (byte)0x16, (byte)0x4b, (byte)0x7a, (byte)0x7b, 
			        (byte)0xfc, (byte)0xf8, (byte)0x19, (byte)0xe2, 
			        (byte)0xe3, (byte)0x95, (byte)0xfb, (byte)0xe7, 
			        (byte)0x3b, (byte)0x56, (byte)0xe0, (byte)0xa3, 
			        (byte)0x87, (byte)0xbd, (byte)0x64, (byte)0x22, 
			        (byte)0x2e, (byte)0x83, (byte)0x1f, (byte)0xd6, 
			        (byte)0x10, (byte)0x27, (byte)0x0c, (byte)0xd7, 
			        (byte)0xea, (byte)0x25, (byte)0x05, (byte)0x54, 
			        (byte)0x97, (byte)0x58, (byte)0xbf, (byte)0x75, 
			        (byte)0xc0, (byte)0x5a, (byte)0x99, (byte)0x4a, 
			        (byte)0x6d, (byte)0x03, (byte)0x4f, (byte)0x65, 
			        (byte)0xf8, (byte)0xf0, (byte)0xe6, (byte)0xfd, 
			        (byte)0xca, (byte)0xea, (byte)0xb1, (byte)0xa3, 
			        (byte)0x4d, (byte)0x4a, (byte)0x6b, (byte)0x4b, 
			        (byte)0x63, (byte)0x6e, (byte)0x07, (byte)0x0a, 
			        (byte)0x38, (byte)0xbc, (byte)0xe7, (byte)0x37
                });
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                    (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA 
                }, 50, new byte[] { (byte)0xDD }, new byte[] {
			        (byte)0xfa, (byte)0x73, (byte)0xb0, (byte)0x08, 
			        (byte)0x9d, (byte)0x56, (byte)0xa2, (byte)0x84, 
			        (byte)0xef, (byte)0xb0, (byte)0xf0, (byte)0x75, 
			        (byte)0x6c, (byte)0x89, (byte)0x0b, (byte)0xe9, 
			        (byte)0xb1, (byte)0xb5, (byte)0xdb, (byte)0xdd, 
			        (byte)0x8e, (byte)0xe8, (byte)0x1a, (byte)0x36, 
			        (byte)0x55, (byte)0xf8, (byte)0x3e, (byte)0x33, 
			        (byte)0xb2, (byte)0x27, (byte)0x9d, (byte)0x39, 
			        (byte)0xbf, (byte)0x3e, (byte)0x84, (byte)0x82, 
			        (byte)0x79, (byte)0xa7, (byte)0x22, (byte)0xc8, 
			        (byte)0x06, (byte)0xb4, (byte)0x85, (byte)0xa4, 
			        (byte)0x7e, (byte)0x67, (byte)0xc8, (byte)0x07, 
			        (byte)0xb9, (byte)0x46, (byte)0xa3, (byte)0x37, 
			        (byte)0xbe, (byte)0xe8, (byte)0x94, (byte)0x26, 
			        (byte)0x74, (byte)0x27, (byte)0x88, (byte)0x59, 
			        (byte)0xe1, (byte)0x32, (byte)0x92, (byte)0xfb
                });
                if (KeySizes.Contains(algorithm.KeySizes, 24))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                    (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, 
                    (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, 
                    (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10, 
                    (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, 
                    (byte)0x15, (byte)0x16, (byte)0x17, (byte)0x18, 
                    (byte)0x19
                }, 50, new byte[] { (byte)0xCD }, new byte[] {
			        (byte)0xb0, (byte)0xba, (byte)0x46, (byte)0x56, 
			        (byte)0x37, (byte)0x45, (byte)0x8c, (byte)0x69, 
			        (byte)0x90, (byte)0xe5, (byte)0xa8, (byte)0xc5, 
			        (byte)0xf6, (byte)0x1d, (byte)0x4a, (byte)0xf7, 
			        (byte)0xe5, (byte)0x76, (byte)0xd9, (byte)0x7f, 
			        (byte)0xf9, (byte)0x4b, (byte)0x87, (byte)0x2d, 
			        (byte)0xe7, (byte)0x6f, (byte)0x80, (byte)0x50, 
			        (byte)0x36, (byte)0x1e, (byte)0xe3, (byte)0xdb, 
			        (byte)0xa9, (byte)0x1c, (byte)0xa5, (byte)0xc1, 
			        (byte)0x1a, (byte)0xa2, (byte)0x5e, (byte)0xb4, 
			        (byte)0xd6, (byte)0x79, (byte)0x27, (byte)0x5c, 
			        (byte)0xc5, (byte)0x78, (byte)0x80, (byte)0x63,
			        (byte)0xa5, (byte)0xf1, (byte)0x97, (byte)0x41, 
			        (byte)0x12, (byte)0x0c, (byte)0x4f, (byte)0x2d, 
			        (byte)0xe2, (byte)0xad, (byte)0xeb, (byte)0xeb, 
			        (byte)0x10, (byte)0xa2, (byte)0x98, (byte)0xdd
                });
                if (KeySizes.Contains(algorithm.KeySizes, 20))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c, 
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c,
                    (byte)0x0c, (byte)0x0c, (byte)0x0c, (byte)0x0c
                }, 1, "Test With Truncation", new byte[] {
			        (byte)0x41, (byte)0x5f, (byte)0xad, (byte)0x62, 
			        (byte)0x71, (byte)0x58, (byte)0x0a, (byte)0x53, 
			        (byte)0x1d, (byte)0x41, (byte)0x79, (byte)0xbc, 
			        (byte)0x89, (byte)0x1d, (byte)0x87, (byte)0xa6
                });
                if (KeySizes.Contains(algorithm.KeySizes, 80))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa
                }, 1, "Test Using Larger Than Block-Size Key - Hash Key First", new byte[] {
			        (byte)0x80, (byte)0xb2, (byte)0x42, (byte)0x63, 
			        (byte)0xc7, (byte)0xc1, (byte)0xa3, (byte)0xeb, 
			        (byte)0xb7, (byte)0x14, (byte)0x93, (byte)0xc1, 
			        (byte)0xdd, (byte)0x7b, (byte)0xe8, (byte)0xb4, 
			        (byte)0x9b, (byte)0x46, (byte)0xd1, (byte)0xf4, 
			        (byte)0x1b, (byte)0x4a, (byte)0xee, (byte)0xc1, 
			        (byte)0x12, (byte)0x1b, (byte)0x01, (byte)0x37, 
			        (byte)0x83, (byte)0xf8, (byte)0xf3, (byte)0x52, 
			        (byte)0x6b, (byte)0x56, (byte)0xd0, (byte)0x37, 
			        (byte)0xe0, (byte)0x5f, (byte)0x25, (byte)0x98, 
			        (byte)0xbd, (byte)0x0f, (byte)0xd2, (byte)0x21, 
			        (byte)0x5d, (byte)0x6a, (byte)0x1e, (byte)0x52, 
			        (byte)0x95, (byte)0xe6, (byte)0x4f, (byte)0x73, 
			        (byte)0xf6, (byte)0x3f, (byte)0x0a, (byte)0xec, 
			        (byte)0x8b, (byte)0x91, (byte)0x5a, (byte)0x98, 
			        (byte)0x5d, (byte)0x78, (byte)0x65, (byte)0x98
                });
                if (KeySizes.Contains(algorithm.KeySizes, 80))
                CAPI.Test.MAC.Test(algorithm, new byte[] { 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
                    (byte)0xaa, (byte)0xaa, (byte)0xaa
                }, 1, "This is a test using a larger than block-size key and " +
                      "a larger than block-size data. The key needs to be hashed " +
                      "before being used by the HMAC algorithm.", new byte[] {
			        (byte)0xe3, (byte)0x7b, (byte)0x6a, (byte)0x77, 
			        (byte)0x5d, (byte)0xc8, (byte)0x7d, (byte)0xba, 
			        (byte)0xa4, (byte)0xdf, (byte)0xa9, (byte)0xf9, 
			        (byte)0x6e, (byte)0x5e, (byte)0x3f, (byte)0xfd, 
			        (byte)0xde, (byte)0xbd, (byte)0x71, (byte)0xf8, 
			        (byte)0x86, (byte)0x72, (byte)0x89, (byte)0x86, 
			        (byte)0x5d, (byte)0xf5, (byte)0xa3, (byte)0x2d, 
			        (byte)0x20, (byte)0xcd, (byte)0xc9, (byte)0x44, 
			        (byte)0xb6, (byte)0x02, (byte)0x2c, (byte)0xac, 
			        (byte)0x3c, (byte)0x49, (byte)0x82, (byte)0xb1, 
			        (byte)0x0d, (byte)0x5e, (byte)0xeb, (byte)0x55, 
			        (byte)0xc3, (byte)0xe4, (byte)0xde, (byte)0x15, 
			        (byte)0x13, (byte)0x46, (byte)0x76, (byte)0xfb, 
			        (byte)0x6d, (byte)0xe0, (byte)0x44, (byte)0x60, 
			        (byte)0x65, (byte)0xc9, (byte)0x74, (byte)0x40, 
			        (byte)0xfa, (byte)0x8c, (byte)0x6a, (byte)0x58
                });
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // AES-CBC-MAC
        ////////////////////////////////////////////////////////////////////////////
        public static void TestAESCMAC(Factory factory, SecurityStore scope) 
        {
            // указать параметры шифрования
            ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_cbc), 
                new ASN1.OctetString(new byte[16])
            ); 
            // указать параметры шифрования блока
            ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_ecb), ASN1.Null.Instance
            ); 
            // создать режим шифрования CBC
            using (Cipher cipherCBC = factory.CreateAlgorithm<Cipher>(scope, cipherParameters))
            {
                // создать режим шифрования блока
                using (IBlockEngine engine = factory.CreateAlgorithm<IBlockEngine>(scope, engineParameters))
                {
                    // создать алгоритм выработки имитовставки
                    using (MAC algorithm = new CAPI.MAC.OMAC1(cipherCBC, engine, 16))
                    { 
                        // указать ключ
                        byte[] key = new byte[] {
                            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16, 
                            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6, 
                            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88, 
                            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
                        };
                        CAPI.Test.MAC.Test(algorithm, key, 1, new byte[] {}, new byte[] {
                            (byte)0xbb, (byte)0x1d, (byte)0x69, (byte)0x29, 
                            (byte)0xe9, (byte)0x59, (byte)0x37, (byte)0x28, 
                            (byte)0x7f, (byte)0xa3, (byte)0x7d, (byte)0x12, 
                            (byte)0x9b, (byte)0x75, (byte)0x67, (byte)0x46
                        });
                        CAPI.Test.MAC.Test(algorithm, key, 1, new byte[] {
                            (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2, 
                            (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96,
                            (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11, 
                            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a
                        }, new byte[] {
                            (byte)0x07, (byte)0x0a, (byte)0x16, (byte)0xb4, 
                            (byte)0x6b, (byte)0x4d, (byte)0x41, (byte)0x44, 
                            (byte)0xf7, (byte)0x9b, (byte)0xdd, (byte)0x9d, 
                            (byte)0xd0, (byte)0x4a, (byte)0x28, (byte)0x7c
                        });
                        CAPI.Test.MAC.Test(algorithm, key, 1, new byte[] {
                            (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2, 
                            (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96, 
                            (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11, 
                            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a, 
                            (byte)0xae, (byte)0x2d, (byte)0x8a, (byte)0x57, 
                            (byte)0x1e, (byte)0x03, (byte)0xac, (byte)0x9c, 
                            (byte)0x9e, (byte)0xb7, (byte)0x6f, (byte)0xac, 
                            (byte)0x45, (byte)0xaf, (byte)0x8e, (byte)0x51, 
                            (byte)0x30, (byte)0xc8, (byte)0x1c, (byte)0x46, 
                            (byte)0xa3, (byte)0x5c, (byte)0xe4, (byte)0x11
                        }, new byte[] {
                            (byte)0xdf, (byte)0xa6, (byte)0x67, (byte)0x47, 
                            (byte)0xde, (byte)0x9a, (byte)0xe6, (byte)0x30, 
                            (byte)0x30, (byte)0xca, (byte)0x32, (byte)0x61, 
                            (byte)0x14, (byte)0x97, (byte)0xc8, (byte)0x27
                        });
                        CAPI.Test.MAC.Test(algorithm, key, 1, new byte[] {
                            (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2, 
                            (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96, 
                            (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11,
                            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a,
                            (byte)0xae, (byte)0x2d, (byte)0x8a, (byte)0x57, 
                            (byte)0x1e, (byte)0x03, (byte)0xac, (byte)0x9c, 
                            (byte)0x9e, (byte)0xb7, (byte)0x6f, (byte)0xac,
                            (byte)0x45, (byte)0xaf, (byte)0x8e, (byte)0x51,
                            (byte)0x30, (byte)0xc8, (byte)0x1c, (byte)0x46,
                            (byte)0xa3, (byte)0x5c, (byte)0xe4, (byte)0x11, 
                            (byte)0xe5, (byte)0xfb, (byte)0xc1, (byte)0x19, 
                            (byte)0x1a, (byte)0x0a, (byte)0x52, (byte)0xef, 
                            (byte)0xf6, (byte)0x9f, (byte)0x24, (byte)0x45, 
                            (byte)0xdf, (byte)0x4f, (byte)0x9b, (byte)0x17, 
                            (byte)0xad, (byte)0x2b, (byte)0x41, (byte)0x7b, 
                            (byte)0xe6, (byte)0x6c, (byte)0x37, (byte)0x10
                        }, new byte[] {
                            (byte)0x51, (byte)0xf0, (byte)0xbe, (byte)0xbf,
                            (byte)0x7e, (byte)0x3b, (byte)0x9d, (byte)0x92,
                            (byte)0xfc, (byte)0x49, (byte)0x74, (byte)0x17, 
                            (byte)0x79, (byte)0x36, (byte)0x3c, (byte)0xfe
                        });
                    }
                }
            }
        }
    }
}

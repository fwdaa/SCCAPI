using System; 

namespace Aladdin.CAPI.GOST.Keyx.GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////////
    // Формирование общего ключа ГОСТ Р 34.10-2012
    ///////////////////////////////////////////////////////////////////////////
    public class ECKeyAgreement2012 : GOSTR3410.ECKeyAgreement
    {
        // конструктор
        public ECKeyAgreement2012(KeyDerive keyDerive) : base(keyDerive) {} 
        // конструктор
        public ECKeyAgreement2012() {}

        // создать алгоритм хэширования
        protected override CAPI.Hash CreateHashAlgorithm(IPrivateKey privateKey, int keySize) 
        {
            // вернуть алгоритм хэширования
            if (keySize == 32) return new Hash.GOSTR3411_2012(256); 
        
            // вернуть алгоритм хэширования
            if (keySize == 64) return new Hash.GOSTR3411_2012(512); 

            // операция не поддерживается
            throw new NotSupportedException(); 
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        protected static void KnownTest(CAPI.Factory factory, SecurityObject scope, 
            IKeyAgreement keyAgreement, string keyOID, string paramOID, 
            Math.BigInteger qx1, Math.BigInteger qy1, Math.BigInteger d1, 
            Math.BigInteger qx2, Math.BigInteger qy2, Math.BigInteger d2, byte[] random, byte[] check)
        {
            // указать идентификатор алгоритма хэширования
            string hashOID = (check.Length == 32) ? 
                ASN1.GOST.OID.gostR3411_2012_256 : ASN1.GOST.OID.gostR3411_2012_512;

            // указать фабрику кодирования
            KeyFactory keyFactory = factory.GetKeyFactory(keyOID); 

            // создать параметры алгоритма
            GOST.GOSTR3410.IECParameters keyParameters = 
                new GOST.GOSTR3410.ECNamedParameters2012(paramOID, hashOID); 
        
            // создать открытый ключ
            IPublicKey publicKey1 = new GOST.GOSTR3410.ECPublicKey(
                keyFactory, keyParameters, new EC.Point(qx1, qy1)
            ); 
            // создать личный ключ
            using (IPrivateKey privateKey1 = new GOST.GOSTR3410.ECPrivateKey(
                factory, null, keyOID, keyParameters, d1))
            {
                // создать открытый ключ
                IPublicKey publicKey2 = new GOST.GOSTR3410.ECPublicKey(
                    keyFactory, keyParameters, new EC.Point(qx2, qy2)
                ); 
                // создать личный ключ
                using (IPrivateKey privateKey2 = new GOST.GOSTR3410.ECPrivateKey(
                    factory, null, keyOID, keyParameters, d2))
                {
                    // выполнить тест
                    KnownTest(scope, keyAgreement, publicKey1, privateKey1, 
                        publicKey2, privateKey2, new byte[][] { random }, check
                    ); 
                }
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование алгоритма
        ////////////////////////////////////////////////////////////////////////////
        public static void Test(CAPI.Factory factory, SecurityObject scope, 
            IKeyAgreement keyAgreement, int[] keySizes) 
        {
            if (KeySizes.Contains(keySizes, 32)) 
            KnownTest(factory, scope, keyAgreement, 
                ASN1.GOST.OID.gostR3410_2012_512, ASN1.GOST.OID.ecc_tc26_2012_512A, 
                new Math.BigInteger(1, new byte[] { 
                    (byte)0xa7, (byte)0xc0, (byte)0xad, (byte)0xb1,
                    (byte)0x27, (byte)0x43, (byte)0xc1, (byte)0x0c,
                    (byte)0x3c, (byte)0x1b, (byte)0xeb, (byte)0x97, 
                    (byte)0xc8, (byte)0xf6, (byte)0x31, (byte)0x24,
                    (byte)0x2f, (byte)0x79, (byte)0x37, (byte)0xa1,
                    (byte)0xde, (byte)0xb6, (byte)0xbc, (byte)0xe5,
                    (byte)0xe6, (byte)0x64, (byte)0xe4, (byte)0x92,
                    (byte)0x61, (byte)0xba, (byte)0xcc, (byte)0xd3,
                    (byte)0xf5, (byte)0xdc, (byte)0x56, (byte)0xec,
                    (byte)0x53, (byte)0xb2, (byte)0xab, (byte)0xb9,
                    (byte)0x0c, (byte)0xa1, (byte)0xeb, (byte)0x70,
                    (byte)0x30, (byte)0x78, (byte)0xba, (byte)0x54,
                    (byte)0x66, (byte)0x55, (byte)0xa8, (byte)0xb9,
                    (byte)0x9f, (byte)0x79, (byte)0x18, (byte)0x8d,
                    (byte)0x20, (byte)0x21, (byte)0xff, (byte)0xab,
                    (byte)0xa4, (byte)0xed, (byte)0xb0, (byte)0xaa
                }), new Math.BigInteger(1, new byte[] { 
                    (byte)0x5a, (byte)0xdb, (byte)0x1c, (byte)0x63,
                    (byte)0xa4, (byte)0xe4, (byte)0x46, (byte)0x5e, 
                    (byte)0x0b, (byte)0xbe, (byte)0xfd, (byte)0x89,
                    (byte)0x7f, (byte)0xb9, (byte)0x01, (byte)0x64,
                    (byte)0x75, (byte)0x93, (byte)0x4c, (byte)0xfa,
                    (byte)0x0f, (byte)0x8c, (byte)0x95, (byte)0xf9,
                    (byte)0x92, (byte)0xea, (byte)0x40, (byte)0x2d,
                    (byte)0x47, (byte)0x92, (byte)0x1f, (byte)0x46,
                    (byte)0x38, (byte)0x2d, (byte)0x00, (byte)0x48,
                    (byte)0x1b, (byte)0x72, (byte)0x03, (byte)0x14,
                    (byte)0xb1, (byte)0x9d, (byte)0x8c, (byte)0x87,
                    (byte)0x8e, (byte)0x75, (byte)0xd8, (byte)0x1b,
                    (byte)0x97, (byte)0x63, (byte)0x35, (byte)0x8d,
                    (byte)0xd3, (byte)0x04, (byte)0xb2, (byte)0xed,
                    (byte)0x3a, (byte)0x36, (byte)0x4e, (byte)0x07,
                    (byte)0xa3, (byte)0x13, (byte)0x46, (byte)0x91
                }), new Math.BigInteger(1, new byte[] {
                    (byte)0x67, (byte)0xb6, (byte)0x3c, (byte)0xa4,
                    (byte)0xac, (byte)0x8d, (byte)0x2b, (byte)0xb3,
                    (byte)0x26, (byte)0x18, (byte)0xd8, (byte)0x92,
                    (byte)0x96, (byte)0xc7, (byte)0x47, (byte)0x6d,
                    (byte)0xbe, (byte)0xb9, (byte)0xf9, (byte)0x04,
                    (byte)0x84, (byte)0x96, (byte)0xf2, (byte)0x02,
                    (byte)0xb1, (byte)0x90, (byte)0x2c, (byte)0xf2,
                    (byte)0xce, (byte)0x41, (byte)0xdb, (byte)0xc2,
                    (byte)0xf8, (byte)0x47, (byte)0x71, (byte)0x2d,
                    (byte)0x96, (byte)0x04, (byte)0x83, (byte)0x45,
                    (byte)0x8d, (byte)0x4b, (byte)0x38, (byte)0x08,
                    (byte)0x67, (byte)0xf4, (byte)0x26, (byte)0xc7,
                    (byte)0xca, (byte)0x0f, (byte)0xf5, (byte)0x78,
                    (byte)0x27, (byte)0x02, (byte)0xdb, (byte)0xc4,
                    (byte)0x4e, (byte)0xe8, (byte)0xfc, (byte)0x72,
                    (byte)0xd9, (byte)0xec, (byte)0x90, (byte)0xc9
                }), new Math.BigInteger(1, new byte[] { 
                    (byte)0x51, (byte)0xa6, (byte)0xd5, (byte)0x4e,
                    (byte)0xe9, (byte)0x32, (byte)0xd1, (byte)0x76,
                    (byte)0xe8, (byte)0x75, (byte)0x91, (byte)0x12,
                    (byte)0x1c, (byte)0xce, (byte)0x5f, (byte)0x39,
                    (byte)0x5c, (byte)0xb2, (byte)0xf2, (byte)0xf1,
                    (byte)0x47, (byte)0x11, (byte)0x4d, (byte)0x95,
                    (byte)0xf4, (byte)0x63, (byte)0xc8, (byte)0xa7,
                    (byte)0xed, (byte)0x74, (byte)0xa9, (byte)0xfc,
                    (byte)0x5e, (byte)0xcd, (byte)0x23, (byte)0x25,
                    (byte)0xa3, (byte)0x5f, (byte)0xb6, (byte)0x38,
                    (byte)0x78, (byte)0x31, (byte)0xea, (byte)0x66,
                    (byte)0xbc, (byte)0x3d, (byte)0x2a, (byte)0xa4,
                    (byte)0x2e, (byte)0xde, (byte)0x35, (byte)0x87,
                    (byte)0x2c, (byte)0xc7, (byte)0x53, (byte)0x72,
                    (byte)0x07, (byte)0x3a, (byte)0x71, (byte)0xb9,
                    (byte)0x83, (byte)0xe1, (byte)0x2f, (byte)0x19
                }), new Math.BigInteger(1, new byte[] { 
                    (byte)0x79, (byte)0x3b, (byte)0xde, (byte)0x5b,
                    (byte)0xf7, (byte)0x28, (byte)0x40, (byte)0xad,
                    (byte)0x22, (byte)0xb0, (byte)0x2a, (byte)0x36,
                    (byte)0x3a, (byte)0xe4, (byte)0x77, (byte)0x2d,
                    (byte)0x4a, (byte)0x52, (byte)0xfc, (byte)0x08,
                    (byte)0xba, (byte)0x1a, (byte)0x20, (byte)0xf7,
                    (byte)0x45, (byte)0x8a, (byte)0x22, (byte)0x2a,
                    (byte)0x13, (byte)0xbf, (byte)0x98, (byte)0xb5,
                    (byte)0x3b, (byte)0xe0, (byte)0x02, (byte)0xd1,
                    (byte)0x97, (byte)0x3f, (byte)0x1e, (byte)0x39,
                    (byte)0x8c, (byte)0xe4, (byte)0x6c, (byte)0x17,
                    (byte)0xda, (byte)0x6d, (byte)0x00, (byte)0xd9,
                    (byte)0xb6, (byte)0xd0, (byte)0x07, (byte)0x6f,
                    (byte)0x82, (byte)0x84, (byte)0xdc, (byte)0xc4,
                    (byte)0x2e, (byte)0x59, (byte)0x9b, (byte)0x4c,
                    (byte)0x41, (byte)0x3b, (byte)0x88, (byte)0x04
                }), new Math.BigInteger(1, new byte[] { 
                    (byte)0xdb, (byte)0xd0, (byte)0x92, (byte)0x13,
                    (byte)0xa5, (byte)0x92, (byte)0xda, (byte)0x5b,
                    (byte)0xbf, (byte)0xd8, (byte)0xed, (byte)0x06,
                    (byte)0x8c, (byte)0xcc, (byte)0xcc, (byte)0xbb,
                    (byte)0xfb, (byte)0xed, (byte)0xa4, (byte)0xfe, 
                    (byte)0xac, (byte)0x96, (byte)0xb9, (byte)0xb4,
                    (byte)0x90, (byte)0x85, (byte)0x91, (byte)0x44,
                    (byte)0x0b, (byte)0x07, (byte)0x14, (byte)0x80,
                    (byte)0x3b, (byte)0x9e, (byte)0xb7, (byte)0x63,
                    (byte)0xef, (byte)0x93, (byte)0x22, (byte)0x66,
                    (byte)0xd4, (byte)0xc0, (byte)0x18, (byte)0x1a,
                    (byte)0x9b, (byte)0x73, (byte)0xea, (byte)0xcf,
                    (byte)0x90, (byte)0x13, (byte)0xef, (byte)0xc6,
                    (byte)0x5e, (byte)0xc0, (byte)0x7c, (byte)0x88,
                    (byte)0x85, (byte)0x15, (byte)0xf1, (byte)0xb6,
                    (byte)0xf7, (byte)0x59, (byte)0xc8, (byte)0x48
                }), new byte[] {
                    (byte)0x1d, (byte)0x80, (byte)0x60, (byte)0x3c, 
                    (byte)0x85, (byte)0x44, (byte)0xc7, (byte)0x27
                } , new byte[] {
                    (byte)0xc9, (byte)0xa9, (byte)0xa7, (byte)0x73, 
                    (byte)0x20, (byte)0xe2, (byte)0xcc, (byte)0x55, 
                    (byte)0x9e, (byte)0xd7, (byte)0x2d, (byte)0xce, 
                    (byte)0x6f, (byte)0x47, (byte)0xe2, (byte)0x19, 
                    (byte)0x2c, (byte)0xce, (byte)0xa9, (byte)0x5f, 
                    (byte)0xa6, (byte)0x48, (byte)0x67, (byte)0x05, 
                    (byte)0x82, (byte)0xc0, (byte)0x54, (byte)0xc0, 
                    (byte)0xef, (byte)0x36, (byte)0xc2, (byte)0x21
                }
            ); 
            if (KeySizes.Contains(keySizes, 64)) 
            KnownTest(factory, scope, keyAgreement, 
                ASN1.GOST.OID.gostR3410_2012_512, ASN1.GOST.OID.ecc_tc26_2012_512A, 
                new Math.BigInteger(1, new byte[] { 
                    (byte)0xa7, (byte)0xc0, (byte)0xad, (byte)0xb1, 
                    (byte)0x27, (byte)0x43, (byte)0xc1, (byte)0x0c, 
                    (byte)0x3c, (byte)0x1b, (byte)0xeb, (byte)0x97,
                    (byte)0xc8, (byte)0xf6, (byte)0x31, (byte)0x24, 
                    (byte)0x2f, (byte)0x79, (byte)0x37, (byte)0xa1,
                    (byte)0xde, (byte)0xb6, (byte)0xbc, (byte)0xe5, 
                    (byte)0xe6, (byte)0x64, (byte)0xe4, (byte)0x92,
                    (byte)0x61, (byte)0xba, (byte)0xcc, (byte)0xd3,
                    (byte)0xf5, (byte)0xdc, (byte)0x56, (byte)0xec,
                    (byte)0x53, (byte)0xb2, (byte)0xab, (byte)0xb9,
                    (byte)0x0c, (byte)0xa1, (byte)0xeb, (byte)0x70,
                    (byte)0x30, (byte)0x78, (byte)0xba, (byte)0x54,
                    (byte)0x66, (byte)0x55, (byte)0xa8, (byte)0xb9,
                    (byte)0x9f, (byte)0x79, (byte)0x18, (byte)0x8d,
                    (byte)0x20, (byte)0x21, (byte)0xff, (byte)0xab,
                    (byte)0xa4, (byte)0xed, (byte)0xb0, (byte)0xaa
                }), new Math.BigInteger(1, new byte[] { 
                    (byte)0x5a, (byte)0xdb, (byte)0x1c, (byte)0x63,
                    (byte)0xa4, (byte)0xe4, (byte)0x46, (byte)0x5e,
                    (byte)0x0b, (byte)0xbe, (byte)0xfd, (byte)0x89, 
                    (byte)0x7f, (byte)0xb9, (byte)0x01, (byte)0x64,
                    (byte)0x75, (byte)0x93, (byte)0x4c, (byte)0xfa,
                    (byte)0x0f, (byte)0x8c, (byte)0x95, (byte)0xf9,
                    (byte)0x92, (byte)0xea, (byte)0x40, (byte)0x2d,
                    (byte)0x47, (byte)0x92, (byte)0x1f, (byte)0x46,
                    (byte)0x38, (byte)0x2d, (byte)0x00, (byte)0x48, 
                    (byte)0x1b, (byte)0x72, (byte)0x03, (byte)0x14,
                    (byte)0xb1, (byte)0x9d, (byte)0x8c, (byte)0x87,
                    (byte)0x8e, (byte)0x75, (byte)0xd8, (byte)0x1b,
                    (byte)0x97, (byte)0x63, (byte)0x35, (byte)0x8d,
                    (byte)0xd3, (byte)0x04, (byte)0xb2, (byte)0xed,
                    (byte)0x3a, (byte)0x36, (byte)0x4e, (byte)0x07,
                    (byte)0xa3, (byte)0x13, (byte)0x46, (byte)0x91
                }), new Math.BigInteger(1, new byte[] {
                    (byte)0x67, (byte)0xb6, (byte)0x3c, (byte)0xa4,                 
                    (byte)0xac, (byte)0x8d, (byte)0x2b, (byte)0xb3,
                    (byte)0x26, (byte)0x18, (byte)0xd8, (byte)0x92,
                    (byte)0x96, (byte)0xc7, (byte)0x47, (byte)0x6d,
                    (byte)0xbe, (byte)0xb9, (byte)0xf9, (byte)0x04,
                    (byte)0x84, (byte)0x96, (byte)0xf2, (byte)0x02,
                    (byte)0xb1, (byte)0x90, (byte)0x2c, (byte)0xf2,
                    (byte)0xce, (byte)0x41, (byte)0xdb, (byte)0xc2,
                    (byte)0xf8, (byte)0x47, (byte)0x71, (byte)0x2d,
                    (byte)0x96, (byte)0x04, (byte)0x83, (byte)0x45,
                    (byte)0x8d, (byte)0x4b, (byte)0x38, (byte)0x08,
                    (byte)0x67, (byte)0xf4, (byte)0x26, (byte)0xc7, 
                    (byte)0xca, (byte)0x0f, (byte)0xf5, (byte)0x78, 
                    (byte)0x27, (byte)0x02, (byte)0xdb, (byte)0xc4, 
                    (byte)0x4e, (byte)0xe8, (byte)0xfc, (byte)0x72,
                    (byte)0xd9, (byte)0xec, (byte)0x90, (byte)0xc9
                }), new Math.BigInteger(1, new byte[] { 
                    (byte)0x51, (byte)0xa6, (byte)0xd5, (byte)0x4e,
                    (byte)0xe9, (byte)0x32, (byte)0xd1, (byte)0x76, 
                    (byte)0xe8, (byte)0x75, (byte)0x91, (byte)0x12,
                    (byte)0x1c, (byte)0xce, (byte)0x5f, (byte)0x39,
                    (byte)0x5c, (byte)0xb2, (byte)0xf2, (byte)0xf1,
                    (byte)0x47, (byte)0x11, (byte)0x4d, (byte)0x95,
                    (byte)0xf4, (byte)0x63, (byte)0xc8, (byte)0xa7,
                    (byte)0xed, (byte)0x74, (byte)0xa9, (byte)0xfc,
                    (byte)0x5e, (byte)0xcd, (byte)0x23, (byte)0x25,
                    (byte)0xa3, (byte)0x5f, (byte)0xb6, (byte)0x38,
                    (byte)0x78, (byte)0x31, (byte)0xea, (byte)0x66,
                    (byte)0xbc, (byte)0x3d, (byte)0x2a, (byte)0xa4,
                    (byte)0x2e, (byte)0xde, (byte)0x35, (byte)0x87,
                    (byte)0x2c, (byte)0xc7, (byte)0x53, (byte)0x72, 
                    (byte)0x07, (byte)0x3a, (byte)0x71, (byte)0xb9,
                    (byte)0x83, (byte)0xe1, (byte)0x2f, (byte)0x19    
                }), new Math.BigInteger(1, new byte[] { 
                    (byte)0x79, (byte)0x3b, (byte)0xde, (byte)0x5b,
                    (byte)0xf7, (byte)0x28, (byte)0x40, (byte)0xad,
                    (byte)0x22, (byte)0xb0, (byte)0x2a, (byte)0x36,
                    (byte)0x3a, (byte)0xe4, (byte)0x77, (byte)0x2d, 
                    (byte)0x4a, (byte)0x52, (byte)0xfc, (byte)0x08,
                    (byte)0xba, (byte)0x1a, (byte)0x20, (byte)0xf7, 
                    (byte)0x45, (byte)0x8a, (byte)0x22, (byte)0x2a, 
                    (byte)0x13, (byte)0xbf, (byte)0x98, (byte)0xb5, 
                    (byte)0x3b, (byte)0xe0, (byte)0x02, (byte)0xd1,
                    (byte)0x97, (byte)0x3f, (byte)0x1e, (byte)0x39, 
                    (byte)0x8c, (byte)0xe4, (byte)0x6c, (byte)0x17,
                    (byte)0xda, (byte)0x6d, (byte)0x00, (byte)0xd9,
                    (byte)0xb6, (byte)0xd0, (byte)0x07, (byte)0x6f,
                    (byte)0x82, (byte)0x84, (byte)0xdc, (byte)0xc4,
                    (byte)0x2e, (byte)0x59, (byte)0x9b, (byte)0x4c, 
                    (byte)0x41, (byte)0x3b, (byte)0x88, (byte)0x04
                }), new Math.BigInteger(1, new byte[] { 
                    (byte)0xdb, (byte)0xd0, (byte)0x92, (byte)0x13,
                    (byte)0xa5, (byte)0x92, (byte)0xda, (byte)0x5b, 
                    (byte)0xbf, (byte)0xd8, (byte)0xed, (byte)0x06,
                    (byte)0x8c, (byte)0xcc, (byte)0xcc, (byte)0xbb, 
                    (byte)0xfb, (byte)0xed, (byte)0xa4, (byte)0xfe,
                    (byte)0xac, (byte)0x96, (byte)0xb9, (byte)0xb4,
                    (byte)0x90, (byte)0x85, (byte)0x91, (byte)0x44,
                    (byte)0x0b, (byte)0x07, (byte)0x14, (byte)0x80,
                    (byte)0x3b, (byte)0x9e, (byte)0xb7, (byte)0x63,
                    (byte)0xef, (byte)0x93, (byte)0x22, (byte)0x66,
                    (byte)0xd4, (byte)0xc0, (byte)0x18, (byte)0x1a,
                    (byte)0x9b, (byte)0x73, (byte)0xea, (byte)0xcf,
                    (byte)0x90, (byte)0x13, (byte)0xef, (byte)0xc6,
                    (byte)0x5e, (byte)0xc0, (byte)0x7c, (byte)0x88,
                    (byte)0x85, (byte)0x15, (byte)0xf1, (byte)0xb6,
                    (byte)0xf7, (byte)0x59, (byte)0xc8, (byte)0x48
                }), new byte[] {
                    (byte)0x1d, (byte)0x80, (byte)0x60, (byte)0x3c, 
                    (byte)0x85, (byte)0x44, (byte)0xc7, (byte)0x27
                } , new byte[] {
                    (byte)0x79, (byte)0xf0, (byte)0x02, (byte)0xa9, 
                    (byte)0x69, (byte)0x40, (byte)0xce, (byte)0x7b, 
                    (byte)0xde, (byte)0x32, (byte)0x59, (byte)0xa5, 
                    (byte)0x2e, (byte)0x01, (byte)0x52, (byte)0x97, 
                    (byte)0xad, (byte)0xaa, (byte)0xd8, (byte)0x45, 
                    (byte)0x97, (byte)0xa0, (byte)0xd2, (byte)0x05, 
                    (byte)0xb5, (byte)0x0e, (byte)0x3e, (byte)0x17, 
                    (byte)0x19, (byte)0xf9, (byte)0x7b, (byte)0xfa, 
                    (byte)0x7e, (byte)0xe1, (byte)0xd2, (byte)0x66, 
                    (byte)0x1f, (byte)0xa9, (byte)0x97, (byte)0x9a, 
                    (byte)0x5a, (byte)0xa2, (byte)0x35, (byte)0xb5, 
                    (byte)0x58, (byte)0xa7, (byte)0xe6, (byte)0xd9, 
                    (byte)0xf8, (byte)0x8f, (byte)0x98, (byte)0x2d, 
                    (byte)0xd6, (byte)0x3f, (byte)0xc3, (byte)0x5a, 
                    (byte)0x8e, (byte)0xc0, (byte)0xdd, (byte)0x5e, 
                    (byte)0x24, (byte)0x2d, (byte)0x3b, (byte)0xdf                
                }
            ); 
        }
    }
}

using System;

namespace Aladdin.CAPI.GOST.Sign.GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения ГОСТ Р 34.10-1994
    ///////////////////////////////////////////////////////////////////////
    public class DHSignHash : SignHash
    {
        public override byte[] Sign(IPrivateKey privateKey, IRand rand, 
            ASN1.ISO.AlgorithmIdentifier hashParameters, byte[] hash)
        {
            // преобразовать тип ключа
            CAPI.GOST.GOSTR3410.IDHPrivateKey privateKeyS = 
                (CAPI.GOST.GOSTR3410.IDHPrivateKey)privateKey;

            // получить параметры алгоритма
            CAPI.GOST.GOSTR3410.IDHParameters parameters = 
                (CAPI.GOST.GOSTR3410.IDHParameters)privateKeyS.Parameters; 

            // извлечь параметры алгоритма
            Math.BigInteger p = parameters.P; Math.BigInteger q = parameters.Q;
            Math.BigInteger a = parameters.G; 

            // извлечь секретное значение
            Math.BigInteger x = privateKeyS.X; int bitsQ = q.BitLength;
            
            // указать начальные условия
            Math.BigInteger r = Math.BigInteger.Zero; 
            Math.BigInteger s = Math.BigInteger.Zero;

            // создать экспоненту
            Math.BigInteger h = Math.Convert.ToBigInteger(hash, Math.Endian.LittleEndian).Mod(q);
        
            // проверить значение 
            if (h.Signum == 0) h = Math.BigInteger.One; 

            // указать генератор случайных чисел
            using (Random random = new Random(rand))
            do {
                // указать начальные условия
                Math.BigInteger k = Math.BigInteger.Zero; 
                
                // до выполнения условий
                while (k.Signum == 0 || k.CompareTo(q) >= 0)
                {
                    // сгенерировать ненулевое число
                    k = new Math.BigInteger(bitsQ, random);
                }
                // вычислить параметр R подписи
                r = a.ModPow(k, p).Mod(q);

                // вычислить параметр S подписи
                s = (k.Multiply(h)).Add(x.Multiply(r)).Mod(q);
            }
            // проверить ограничение
            while (r.Signum == 0 || s.Signum == 0); 

            // выделить память для подписи
            int len = (bitsQ + 7) / 8 * 2; byte[] signature = new byte[len]; 

            // закодировать значения R и S
            Math.Convert.FromBigInteger(s, Math.Endian.BigEndian, signature,       0, len / 2); 
            Math.Convert.FromBigInteger(r, Math.Endian.BigEndian, signature, len / 2, len / 2); 
        
            return signature;
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        protected static void KnownTest(CAPI.Factory factory, SecurityObject scope, 
            SignHash signHash, string paramOID, string hashOID, Math.BigInteger y, 
            Math.BigInteger x, byte[] k, byte[] hash, byte[] signature) 
        {
            // указать фабрику кодирования
            KeyFactory keyFactory = new GOST.GOSTR3410.DHKeyFactory(
                ASN1.GOST.OID.gostR3410_1994
            ); 
            // создать параметры алгоритма
            GOST.GOSTR3410.IDHParameters keyParameters = 
                new GOST.GOSTR3410.DHNamedParameters(paramOID, hashOID, null); 

            // создать открытый ключ
            IPublicKey publicKey = new GOST.GOSTR3410.DHPublicKey(
                keyFactory, keyParameters, y
            ); 
            // создать личный ключ
            using (IPrivateKey privateKey = new GOST.GOSTR3410.DHPrivateKey(
                factory, null, publicKey.KeyOID, keyParameters, x))
            {
                // выполнить тест
                KnownTest(scope, signHash, publicKey, privateKey, 
                    new byte[][] { k }, null, hash, signature
                ); 
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование алгоритма
        ////////////////////////////////////////////////////////////////////////////
        public static void Test(CAPI.Factory factory, SecurityObject scope, SignHash signHash) 
        {
            // выполнить тест
            KnownTest(factory, scope, signHash, 
                ASN1.GOST.OID.signs_test, ASN1.GOST.OID.hashes_test, 
                new Math.BigInteger(1, new byte[] { 
                (byte)0xEE, (byte)0x19, (byte)0x02, (byte)0xA4, 
                (byte)0x06, (byte)0x92, (byte)0xD2, (byte)0x73, 
                (byte)0xED, (byte)0xC1, (byte)0xB5, (byte)0xAD, 
                (byte)0xC5, (byte)0x5F, (byte)0x91, (byte)0x12, 
                (byte)0x8E, (byte)0x35, (byte)0xF9, (byte)0xD1, 
                (byte)0x65, (byte)0xFA, (byte)0x99, (byte)0x01, 
                (byte)0xCA, (byte)0xF0, (byte)0x0D, (byte)0x27, 
                (byte)0x01, (byte)0x8B, (byte)0xA6, (byte)0xDF, 
                (byte)0x32, (byte)0x45, (byte)0x19, (byte)0xC1, 
                (byte)0x1A, (byte)0x6E, (byte)0x27, (byte)0x25, 
                (byte)0x26, (byte)0x58, (byte)0x9C, (byte)0xD6, 
                (byte)0xE6, (byte)0xA2, (byte)0xED, (byte)0xDA, 
                (byte)0xAF, (byte)0xE1, (byte)0xC3, (byte)0x08, 
                (byte)0x12, (byte)0x59, (byte)0xBE, (byte)0x9F, 
                (byte)0xCE, (byte)0xE6, (byte)0x67, (byte)0xA2, 
                (byte)0x70, (byte)0x1F, (byte)0x43, (byte)0x52        
            }), new Math.BigInteger(1, new byte[] { 
                (byte)0x30, (byte)0x36, (byte)0x31, (byte)0x45, 
                (byte)0x38, (byte)0x30, (byte)0x38, (byte)0x30, 
                (byte)0x34, (byte)0x36, (byte)0x30, (byte)0x45, 
                (byte)0x42, (byte)0x35, (byte)0x32, (byte)0x44, 
                (byte)0x35, (byte)0x32, (byte)0x42, (byte)0x34, 
                (byte)0x31, (byte)0x41, (byte)0x32, (byte)0x37, 
                (byte)0x38, (byte)0x32, (byte)0x43, (byte)0x31, 
                (byte)0x38, (byte)0x44, (byte)0x30, (byte)0x46,  
            }), new byte[] { 
                (byte)0x90, (byte)0xF3, (byte)0xA5, (byte)0x64, 
                (byte)0x43, (byte)0x92, (byte)0x42, (byte)0xF5, 
                (byte)0x18, (byte)0x6E, (byte)0xBB, (byte)0x22, 
                (byte)0x4C, (byte)0x8E, (byte)0x22, (byte)0x38, 
                (byte)0x11, (byte)0xB7, (byte)0x10, (byte)0x5C, 
                (byte)0x64, (byte)0xE4, (byte)0xF5, (byte)0x39, 
                (byte)0x08, (byte)0x07, (byte)0xE6, (byte)0x36, 
                (byte)0x2D, (byte)0xF4, (byte)0xC7, (byte)0x2A
            }, new byte[] {
                (byte)0x30, (byte)0x42, (byte)0x45, (byte)0x31, 
                (byte)0x36, (byte)0x41, (byte)0x45, (byte)0x34,
                (byte)0x42, (byte)0x43, (byte)0x41, (byte)0x37,
                (byte)0x45, (byte)0x33, (byte)0x36, (byte)0x43,
                (byte)0x39, (byte)0x31, (byte)0x37, (byte)0x34,
                (byte)0x45, (byte)0x34, (byte)0x31, (byte)0x44,
                (byte)0x36, (byte)0x42, (byte)0x45, (byte)0x32, 
                (byte)0x41, (byte)0x45, (byte)0x34, (byte)0x35
            }, new byte[] {
                (byte)0x3F, (byte)0x0D, (byte)0xD5, (byte)0xD4,
                (byte)0x40, (byte)0x0D, (byte)0x47, (byte)0xC0,
                (byte)0x8E, (byte)0x4C, (byte)0xE5, (byte)0x05,
                (byte)0xFF, (byte)0x74, (byte)0x34, (byte)0xB6,
                (byte)0xDB, (byte)0xF7, (byte)0x29, (byte)0x59,
                (byte)0x2E, (byte)0x37, (byte)0xC7, (byte)0x48,
                (byte)0x56, (byte)0xDA, (byte)0xB8, (byte)0x51,
                (byte)0x15, (byte)0xA6, (byte)0x09, (byte)0x55,
                (byte)0x3E, (byte)0x5F, (byte)0x89, (byte)0x5E, 
                (byte)0x27, (byte)0x6D, (byte)0x81, (byte)0xD2,
                (byte)0xD5, (byte)0x2C, (byte)0x07, (byte)0x63,
                (byte)0x27, (byte)0x0A, (byte)0x45, (byte)0x81,
                (byte)0x57, (byte)0xB7, (byte)0x84, (byte)0xC5,
                (byte)0x7A, (byte)0xBD, (byte)0xBD, (byte)0x80,
                (byte)0x7B, (byte)0xC4, (byte)0x4F, (byte)0xD4,
                (byte)0x3A, (byte)0x32, (byte)0xAC, (byte)0x06
            }); 
        }
    }
}
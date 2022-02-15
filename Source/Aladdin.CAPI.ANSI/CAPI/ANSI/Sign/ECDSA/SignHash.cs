using System;

namespace Aladdin.CAPI.ANSI.Sign.ECDSA
{
    ///////////////////////////////////////////////////////////////////////
    // Алгоритм подписи ECDSA
    ///////////////////////////////////////////////////////////////////////
    public class SignHash : CAPI.SignHash
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 

        public override byte[] Sign(CAPI.IPrivateKey privateKey, IRand rand, 
            ASN1.ISO.AlgorithmIdentifier hashParameters, byte[] hash)
        {
            // получить параметры алгоритма
            X962.IParameters ecParameters = (X962.IParameters)privateKey.Parameters; 

            // преобразовать тип ключа
            X962.IPrivateKey ecPrivateKey = (X962.IPrivateKey)privateKey;
        
            // указать эллиптическую кривую
            EC.Curve ec = ecParameters.Curve; hash = (byte[])hash.Clone();
        
            // извлечь параметры алгоритма
            Math.BigInteger n = ecParameters.Order; int bitsN = n.BitLength; 
            
            // указать поле для вычислений
            Math.Fp.Field fn = new Math.Fp.Field(n); 

            // выделить первые биты хэш-значения
            if (hash.Length > (bitsN + 7) / 8) hash = Arrays.CopyOf(hash, 0, (bitsN + 7) / 8); 
        
            // при необходимости
            if (hash.Length == (bitsN + 7) / 8 && (bitsN % 8) != 0) 
            {
                // обнулить неиспользуемые биты
                hash[0] &= (byte)((1 << (bitsN % 8)) - 1); 
            }
            // преобразовать хэш-значение в число
            Math.BigInteger e = Math.Convert.ToBigInteger(hash, Endian).Mod(n);  

            // инициализировать переменные
            Math.BigInteger r = null; Math.BigInteger s = null;

            // указать генератор случайных чисел
            using (Random random = new Random(rand))
            do { 
                // сгенерировать случайное число
                Math.BigInteger k; do { k = new Math.BigInteger(bitsN, random); }

                // проверить выполнение требуемых условий
                while (k.Signum == 0 || k.CompareTo(n) >= 0); 

                // умножить базовую точку на число
                EC.Point R = ec.Multiply(ecParameters.Generator, k); r = R.X.Mod(n); 

                // вычислить s = k^{-1}(e + rd) mod n
                s = fn.Product(fn.Invert(k), fn.Add(e, fn.Product(r, ecPrivateKey.D))); 
            }
            // проверить выполнение условия
            while (r.Signum == 0 || s.Signum == 0); 

            // закодировать значение подписи
            ASN1.ANSI.X962.ECDSASigValue signature = 
                new ASN1.ANSI.X962.ECDSASigValue(
                    new ASN1.Integer(r), new ASN1.Integer(s), null, null
            ); 
		    // вернуть значение подписи
		    return signature.Encoded; 
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        protected static void KnownTest(CAPI.Factory factory, SecurityObject scope, 
            CAPI.SignHash signHash, CAPI.Hash sha1, string paramOID, 
            Math.BigInteger d, byte[] encodedQ, byte[] k, 
            byte[] message, Math.BigInteger r, Math.BigInteger s)
        {
            // указать фабрику алгоритмов
            KeyFactory keyFactory = new X962.KeyFactory(ASN1.ANSI.OID.x962_ec_public_key); 

            // закодировать открытый ключ
            ASN1.ISO.PKIX.SubjectPublicKeyInfo publicKeyInfo = new ASN1.ISO.PKIX.SubjectPublicKeyInfo(
                new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(keyFactory.KeyOID), new ASN1.ObjectIdentifier(paramOID)
                ), new ASN1.BitString(encodedQ)
            ); 
            // создать открытый ключ
            IPublicKey publicKey = keyFactory.DecodePublicKey(publicKeyInfo); 

            // создать личный ключ
            using (IPrivateKey privateKey = new X962.PrivateKey(
                factory, null, keyFactory.KeyOID, (X962.IParameters)publicKey.Parameters, d)) 
            {
                // указать параметры алгоритма хэширования
                ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
                ); 
                // вычислить хэш-значение
                byte[] hash = sha1.HashData(message, 0, message.Length); 
            
                // закодировать подпись
                ASN1.ANSI.X962.ECDSASigValue signature = 
                    new ASN1.ANSI.X962.ECDSASigValue(
                        new ASN1.Integer(r), new ASN1.Integer(s), null, null
                ); 
                // выполнить тест
                KnownTest(scope, signHash, publicKey, privateKey, 
                    new byte[][] {k}, hashParameters, hash, signature.Encoded
                ); 
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование алгоритма
        ////////////////////////////////////////////////////////////////////////////
        public static void Test(CAPI.Factory factory, SecurityObject scope, 
            CAPI.SignHash signHash, CAPI.Hash sha1)
        {
            KnownTest(factory, scope, signHash, sha1, 
                ASN1.ANSI.OID.x962_curves_c2tnb191v1, 
                new Math.BigInteger(1, new byte[] {
                (byte)0x34, (byte)0x05, (byte)0x62, (byte)0xE1, 
                (byte)0xDD, (byte)0xA3, (byte)0x32, (byte)0xF9, 
                (byte)0xD2, (byte)0xAE, (byte)0xC1, (byte)0x68, 
                (byte)0x24, (byte)0x9B, (byte)0x56, (byte)0x96, 
                (byte)0xEE, (byte)0x39, (byte)0xD0, (byte)0xED, 
                (byte)0x4D, (byte)0x03, (byte)0x76, (byte)0x0F, 
            }), new byte[] {
                (byte)0x04, (byte)0x5D, (byte)0xE3, (byte)0x7E, 
                (byte)0x75, (byte)0x6B, (byte)0xD5, (byte)0x5D, 
                (byte)0x72, (byte)0xE3, (byte)0x76, (byte)0x8C, 
                (byte)0xB3, (byte)0x96, (byte)0xFF, (byte)0xEB, 
                (byte)0x96, (byte)0x26, (byte)0x14, (byte)0xDE, 
                (byte)0xA4, (byte)0xCE, (byte)0x28, (byte)0xA2, 
                (byte)0xE7, (byte)0x55, (byte)0xC0, (byte)0xE0, 
                (byte)0xE0, (byte)0x2F, (byte)0x5F, (byte)0xB1, 
                (byte)0x32, (byte)0xCA, (byte)0xF4, (byte)0x16, 
                (byte)0xEF, (byte)0x85, (byte)0xB2, (byte)0x29, 
                (byte)0xBB, (byte)0xB8, (byte)0xE1, (byte)0x35, 
                (byte)0x20, (byte)0x03, (byte)0x12, (byte)0x5B, 
                (byte)0xA1        
            }, new byte[] {
                (byte)0x3E, (byte)0xEA, (byte)0xCE, (byte)0x72, 
                (byte)0xB4, (byte)0x91, (byte)0x9D, (byte)0x99, 
                (byte)0x17, (byte)0x38, (byte)0xD5, (byte)0x21, 
                (byte)0x87, (byte)0x9F, (byte)0x78, (byte)0x7C, 
                (byte)0xB5, (byte)0x90, (byte)0xAF, (byte)0xF8, 
                (byte)0x18, (byte)0x9D, (byte)0x2B, (byte)0x69, 
            }, new byte[] {
                (byte)0x61, (byte)0x62, (byte)0x63
            }, new Math.BigInteger(1, new byte[] {
                (byte)0x03, (byte)0x8E, (byte)0x5A, (byte)0x11, 
                (byte)0xFB, (byte)0x55, (byte)0xE4, (byte)0xC6, 
                (byte)0x54, (byte)0x71, (byte)0xDC, (byte)0xD4, 
                (byte)0x99, (byte)0x84, (byte)0x52, (byte)0xB1, 
                (byte)0xE0, (byte)0x2D, (byte)0x8A, (byte)0xF7, 
                (byte)0x09, (byte)0x9B, (byte)0xB9, (byte)0x30, 
            }), new Math.BigInteger(1, new byte[] {
                (byte)0x0C, (byte)0x9A, (byte)0x08, (byte)0xC3, 
                (byte)0x44, (byte)0x68, (byte)0xC2, (byte)0x44, 
                (byte)0xB4, (byte)0xE5, (byte)0xD6, (byte)0xB2, 
                (byte)0x1B, (byte)0x3C, (byte)0x68, (byte)0x36, 
                (byte)0x28, (byte)0x07, (byte)0x41, (byte)0x60, 
                (byte)0x20, (byte)0x32, (byte)0x8B, (byte)0x6E, 
            })); 
            KnownTest(factory, scope, signHash, sha1, 
                ASN1.ANSI.OID.x962_curves_c2tnb239v1, 
                new Math.BigInteger(1, new byte[] {
                (byte)0x15, (byte)0x1A, (byte)0x30, (byte)0xA6, 
                (byte)0xD8, (byte)0x43, (byte)0xDB, (byte)0x3B, 
                (byte)0x25, (byte)0x06, (byte)0x3C, (byte)0x51, 
                (byte)0x08, (byte)0x25, (byte)0x5C, (byte)0xC4, 
                (byte)0x44, (byte)0x8E, (byte)0xC0, (byte)0xF4, 
                (byte)0xD4, (byte)0x26, (byte)0xD4, (byte)0xEC, 
                (byte)0x88, (byte)0x45, (byte)0x02, (byte)0x22, 
                (byte)0x9C, (byte)0x96, 
            }), new byte[] {
                (byte)0x04, (byte)0x58, (byte)0x94, (byte)0x60, 
                (byte)0x9C, (byte)0xCE, (byte)0xCF, (byte)0x9A, 
                (byte)0x92, (byte)0x53, (byte)0x3F, (byte)0x63, 
                (byte)0x0D, (byte)0xE7, (byte)0x13, (byte)0xA9, 
                (byte)0x58, (byte)0xE9, (byte)0x6C, (byte)0x97, 
                (byte)0xCC, (byte)0xB8, (byte)0xF5, (byte)0xAB, 
                (byte)0xB5, (byte)0xA6, (byte)0x88, (byte)0xA2, 
                (byte)0x38, (byte)0xDE, (byte)0xED, (byte)0x6D, 
                (byte)0xC2, (byte)0xD9, (byte)0xD0, (byte)0xC9, 
                (byte)0x4E, (byte)0xBF, (byte)0xB7, (byte)0xD5, 
                (byte)0x26, (byte)0xBA, (byte)0x6A, (byte)0x61, 
                (byte)0x76, (byte)0x41, (byte)0x75, (byte)0xB9, 
                (byte)0x9C, (byte)0xB6, (byte)0x01, (byte)0x1E, 
                (byte)0x20, (byte)0x47, (byte)0xF9, (byte)0xF0, 
                (byte)0x67, (byte)0x29, (byte)0x3F, (byte)0x57, 
                (byte)0xF5        
            }, new byte[] {
                (byte)0x18, (byte)0xD1, (byte)0x14, (byte)0xBD, 
                (byte)0xF4, (byte)0x7E, (byte)0x29, (byte)0x13, 
                (byte)0x46, (byte)0x3E, (byte)0x50, (byte)0x37, 
                (byte)0x5D, (byte)0xC9, (byte)0x27, (byte)0x84, 
                (byte)0xA1, (byte)0x49, (byte)0x34, (byte)0xA1, 
                (byte)0x24, (byte)0xF8, (byte)0x3D, (byte)0x28, 
                (byte)0xCA, (byte)0xF9, (byte)0x7C, (byte)0x5D, 
                (byte)0x8A, (byte)0xAB, 
            }, new byte[] {
                (byte)0x61, (byte)0x62, (byte)0x63
            }, new Math.BigInteger(1, new byte[] {
                (byte)0x03, (byte)0x21, (byte)0x0D, (byte)0x71, 
                (byte)0xEF, (byte)0x6C, (byte)0x10, (byte)0x15, 
                (byte)0x7C, (byte)0x0D, (byte)0x10, (byte)0x53, 
                (byte)0xDF, (byte)0xF9, (byte)0x3E, (byte)0x8B, 
                (byte)0x08, (byte)0x5F, (byte)0x1E, (byte)0x9B, 
                (byte)0xC2, (byte)0x24, (byte)0x01, (byte)0xF7, 
                (byte)0xA2, (byte)0x47, (byte)0x98, (byte)0xA6, 
                (byte)0x3C, (byte)0x00, 
            }), new Math.BigInteger(1, new byte[] {
                (byte)0x1C, (byte)0x8C, (byte)0x43, (byte)0x43, 
                (byte)0xA8, (byte)0xEC, (byte)0xBF, (byte)0x7C, 
                (byte)0x4D, (byte)0x4E, (byte)0x48, (byte)0xF7, 
                (byte)0xD7, (byte)0x6D, (byte)0x56, (byte)0x58, 
                (byte)0xBC, (byte)0x02, (byte)0x7C, (byte)0x77, 
                (byte)0x08, (byte)0x6E, (byte)0xC8, (byte)0xB1, 
                (byte)0x00, (byte)0x97, (byte)0xDE, (byte)0xB3, 
                (byte)0x07, (byte)0xD6, 
            })); 
            KnownTest(factory, scope, signHash, sha1, 
                ASN1.ANSI.OID.x962_curves_prime192v1, 
                new Math.BigInteger(1, new byte[] {
                (byte)0x1A, (byte)0x8D, (byte)0x59, (byte)0x8F, 
                (byte)0xC1, (byte)0x5B, (byte)0xF0, (byte)0xFD, 
                (byte)0x89, (byte)0x03, (byte)0x0B, (byte)0x5C, 
                (byte)0xB1, (byte)0x11, (byte)0x1A, (byte)0xEB, 
                (byte)0x92, (byte)0xAE, (byte)0x8B, (byte)0xAF, 
                (byte)0x5E, (byte)0xA4, (byte)0x75, (byte)0xFB, 
            }), new byte[] {
                (byte)0x02, (byte)0x62, (byte)0xB1, (byte)0x2D, 
                (byte)0x60, (byte)0x69, (byte)0x0C, (byte)0xDC, 
                (byte)0xF3, (byte)0x30, (byte)0xBA, (byte)0xBA, 
                (byte)0xB6, (byte)0xE6, (byte)0x97, (byte)0x63, 
                (byte)0xB4, (byte)0x71, (byte)0xF9, (byte)0x94, 
                (byte)0xDD, (byte)0x70, (byte)0x2D, (byte)0x16, 
                (byte)0xA5        
            }, new byte[] {
                (byte)0xFA, (byte)0x6D, (byte)0xE2, (byte)0x97, 
                (byte)0x46, (byte)0xBB, (byte)0xEB, (byte)0x7F, 
                (byte)0x8B, (byte)0xB1, (byte)0xE7, (byte)0x61, 
                (byte)0xF8, (byte)0x5F, (byte)0x7D, (byte)0xFB, 
                (byte)0x29, (byte)0x83, (byte)0x16, (byte)0x9D, 
                (byte)0x82, (byte)0xFA, (byte)0x2F, (byte)0x4E, 
            }, new byte[] {
                (byte)0x61, (byte)0x62, (byte)0x63
            }, new Math.BigInteger(1, new byte[] {
                (byte)0x88, (byte)0x50, (byte)0x52, (byte)0x38, 
                (byte)0x0F, (byte)0xF1, (byte)0x47, (byte)0xB7, 
                (byte)0x34, (byte)0xC3, (byte)0x30, (byte)0xC4, 
                (byte)0x3D, (byte)0x39, (byte)0xB2, (byte)0xC4, 
                (byte)0xA8, (byte)0x9F, (byte)0x29, (byte)0xB0, 
                (byte)0xF7, (byte)0x49, (byte)0xFE, (byte)0xAD, 
            }), new Math.BigInteger(1, new byte[] {
                (byte)0xE9, (byte)0xEC, (byte)0xC7, (byte)0x81, 
                (byte)0x06, (byte)0xDE, (byte)0xF8, (byte)0x2B, 
                (byte)0xF1, (byte)0x07, (byte)0x0C, (byte)0xF1, 
                (byte)0xD4, (byte)0xD8, (byte)0x04, (byte)0xC3, 
                (byte)0xCB, (byte)0x39, (byte)0x00, (byte)0x46, 
                (byte)0x95, (byte)0x1D, (byte)0xF6, (byte)0x86, 
            })); 
            KnownTest(factory, scope, signHash, sha1, 
                ASN1.ANSI.OID.x962_curves_prime239v1, 
                new Math.BigInteger(1, new byte[] {
                (byte)0x7E, (byte)0xF7, (byte)0xC6, (byte)0xFA, 
                (byte)0xBE, (byte)0xFF, (byte)0xFD, (byte)0xEA, 
                (byte)0x86, (byte)0x42, (byte)0x06, (byte)0xE8, 
                (byte)0x0B, (byte)0x0B, (byte)0x08, (byte)0xA9, 
                (byte)0x33, (byte)0x1E, (byte)0xD9, (byte)0x3E, 
                (byte)0x69, (byte)0x85, (byte)0x61, (byte)0xB6, 
                (byte)0x4C, (byte)0xA0, (byte)0xF7, (byte)0x77, 
                (byte)0x7F, (byte)0x3D, 
            }), new byte[] {
                (byte)0x02, (byte)0x5B, (byte)0x6D, (byte)0xC5, 
                (byte)0x3B, (byte)0xC6, (byte)0x1A, (byte)0x25, 
                (byte)0x48, (byte)0xFF, (byte)0xB0, (byte)0xF6, 
                (byte)0x71, (byte)0x47, (byte)0x2D, (byte)0xE6, 
                (byte)0xC9, (byte)0x52, (byte)0x1A, (byte)0x9D, 
                (byte)0x2D, (byte)0x25, (byte)0x34, (byte)0xE6, 
                (byte)0x5A, (byte)0xBF, (byte)0xCB, (byte)0xD5, 
                (byte)0xFE, (byte)0x0C, (byte)0x70        
            }, new byte[] {
                (byte)0x65, (byte)0x6C, (byte)0x71, (byte)0x96, 
                (byte)0xBF, (byte)0x87, (byte)0xDC, (byte)0xC5, 
                (byte)0xD1, (byte)0xF1, (byte)0x02, (byte)0x09, 
                (byte)0x06, (byte)0xDF, (byte)0x27, (byte)0x82, 
                (byte)0x36, (byte)0x0D, (byte)0x36, (byte)0xB2, 
                (byte)0xDE, (byte)0x7A, (byte)0x17, (byte)0xEC, 
                (byte)0xE3, (byte)0x7D, (byte)0x50, (byte)0x37, 
                (byte)0x84, (byte)0xAF, 
            }, new byte[] {
                (byte)0x61, (byte)0x62, (byte)0x63
            }, new Math.BigInteger(1, new byte[] {
                (byte)0x2C, (byte)0xB7, (byte)0xF3, (byte)0x68, 
                (byte)0x03, (byte)0xEB, (byte)0xB9, (byte)0xC4, 
                (byte)0x27, (byte)0xC5, (byte)0x8D, (byte)0x82, 
                (byte)0x65, (byte)0xF1, (byte)0x1F, (byte)0xC5, 
                (byte)0x08, (byte)0x47, (byte)0x47, (byte)0x13, 
                (byte)0x30, (byte)0x78, (byte)0xFC, (byte)0x27, 
                (byte)0x9D, (byte)0xE8, (byte)0x74, (byte)0xFB, 
                (byte)0xEC, (byte)0xB0, 
            }), new Math.BigInteger(1, new byte[] {
                (byte)0x2E, (byte)0xEA, (byte)0xE9, (byte)0x88, 
                (byte)0x10, (byte)0x4E, (byte)0x9C, (byte)0x22, 
                (byte)0x34, (byte)0xA3, (byte)0xC2, (byte)0xBE, 
                (byte)0xB1, (byte)0xF5, (byte)0x3B, (byte)0xFA, 
                (byte)0x5D, (byte)0xC1, (byte)0x1F, (byte)0xF3, 
                (byte)0x6A, (byte)0x87, (byte)0x5D, (byte)0x1E, 
                (byte)0x3C, (byte)0xCB, (byte)0x1F, (byte)0x7E, 
                (byte)0x45, (byte)0xCF, 
            })); 
        }
    }
}
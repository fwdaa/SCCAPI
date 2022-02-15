using System;
using System.IO;

namespace Aladdin.CAPI.ANSI.Sign.ECDSA
{
    ///////////////////////////////////////////////////////////////////////
    // Алгоритм проверки подписи ECDSA
    ///////////////////////////////////////////////////////////////////////
    public class VerifyHash : CAPI.VerifyHash
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 

        public override void Verify(CAPI.IPublicKey publicKey, 
            ASN1.ISO.AlgorithmIdentifier hashParameters, byte[] hash, byte[] signature) 
        {
            // получить параметры алгоритма
            X962.IParameters ecParameters = (X962.IParameters)publicKey.Parameters; 

            // преобразовать тип ключа
            X962.IPublicKey ecPublicKey = (X962.IPublicKey)publicKey;

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
            try { 
                // раскодировать подпись
                ASN1.IEncodable encodedSignature = ASN1.Encodable.Decode(signature); 

                // в зависимости от типа подписи
                if (encodedSignature.Tag == ASN1.Tag.Sequence)
                {
                    // преобразовать тип подписи
                    ASN1.ANSI.X962.ECDSASigValue decodedSignature = 
                        new ASN1.ANSI.X962.ECDSASigValue(encodedSignature); 
            
                    // извлечь значения r и s
                    Math.BigInteger r = decodedSignature.R.Value; 
                    Math.BigInteger s = decodedSignature.S.Value; 

                    // проверить корректность r и s
                    if (r.Signum == 0 || r.CompareTo(n) >= 0) throw new SignatureException(); 
                    if (s.Signum == 0 || s.CompareTo(n) >= 0) throw new SignatureException(); 
                
                    // вычислить u1 = es^{-1} mod n
                    Math.BigInteger s1 = fn.Invert(s); Math.BigInteger u1 = fn.Product(e, s1); 

                    // вычислить u2 = rs^{-1} mod n
                    Math.BigInteger u2 = fn.Product(r, s1); 
                
                    // вычислить R = u1G + u2Q
                    EC.Point R = ec.MultiplySum(ecParameters.Generator, u1, ecPublicKey.Q, u2); 
                
                    // проверить на бесконечную точку
                    if (Object.ReferenceEquals(R, EC.Point.Infinity)) throw new SignatureException();
                
                    // проверить совпадение
                    if (!R.X.Mod(n).Equals(r)) throw new SignatureException();  
                }
                // в зависимости от типа подписи
                else if (encodedSignature.Tag == ASN1.Tag.Context(0))
                {
                    // преобразовать тип подписи
                    ASN1.ANSI.X962.ECDSAFullR decodedSignature = 
                        new ASN1.ANSI.X962.ECDSAFullR(
                            ASN1.Encodable.Decode(encodedSignature.Content)
                    ); 
                    // извлечь значение R 
                    EC.Point R = ec.Decode(decodedSignature.R.Value); 
                
                    // извлечь значение s 
                    Math.BigInteger r = R.X.Mod(n); Math.BigInteger s = decodedSignature.S.Value;
                
                    // проверить корректность r и s
                    if (r.Signum == 0 || r.CompareTo(n) >= 0) throw new SignatureException(); 
                    if (s.Signum == 0 || s.CompareTo(n) >= 0) throw new SignatureException(); 
                
                    // вычислить eG + rQ
                    EC.Point right = ec.MultiplySum(ecParameters.Generator, e, ecPublicKey.Q, r);

                    // проверить корректность подписи
                    if (!ec.Multiply(R, s).Equals(right)) throw new SignatureException(); 
                }
                // при ошибке выбросить исключение
                else throw new SignatureException(); 
            }
            // при ошибке выбросить исключение
            catch (IOException ex) { throw new SignatureException(ex); }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        protected static void KnownTest(CAPI.VerifyHash verifyHash, 
            CAPI.Hash sha1, string paramOID, byte[] encodedQ, 
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
            // проверить подпись хэш-значения
            KnownTest(verifyHash, publicKey, hashParameters, hash, signature.Encoded); 
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование алгоритма
        ////////////////////////////////////////////////////////////////////////////
        public static void Test(CAPI.VerifyHash verifyHash, CAPI.Hash sha1)
        {
            KnownTest(verifyHash, sha1, 
                ASN1.ANSI.OID.x962_curves_c2tnb191v1, new byte[] {
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
            KnownTest(verifyHash, sha1, 
                ASN1.ANSI.OID.x962_curves_c2tnb239v1, new byte[] {
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
            KnownTest(verifyHash, sha1, 
                ASN1.ANSI.OID.x962_curves_prime192v1, new byte[] {
                (byte)0x02, (byte)0x62, (byte)0xB1, (byte)0x2D, 
                (byte)0x60, (byte)0x69, (byte)0x0C, (byte)0xDC, 
                (byte)0xF3, (byte)0x30, (byte)0xBA, (byte)0xBA, 
                (byte)0xB6, (byte)0xE6, (byte)0x97, (byte)0x63, 
                (byte)0xB4, (byte)0x71, (byte)0xF9, (byte)0x94, 
                (byte)0xDD, (byte)0x70, (byte)0x2D, (byte)0x16, 
                (byte)0xA5        
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
            KnownTest(verifyHash, sha1, 
                ASN1.ANSI.OID.x962_curves_prime239v1, new byte[] {
                (byte)0x02, (byte)0x5B, (byte)0x6D, (byte)0xC5, 
                (byte)0x3B, (byte)0xC6, (byte)0x1A, (byte)0x25, 
                (byte)0x48, (byte)0xFF, (byte)0xB0, (byte)0xF6, 
                (byte)0x71, (byte)0x47, (byte)0x2D, (byte)0xE6, 
                (byte)0xC9, (byte)0x52, (byte)0x1A, (byte)0x9D, 
                (byte)0x2D, (byte)0x25, (byte)0x34, (byte)0xE6, 
                (byte)0x5A, (byte)0xBF, (byte)0xCB, (byte)0xD5, 
                (byte)0xFE, (byte)0x0C, (byte)0x70        
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
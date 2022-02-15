using System;

namespace Aladdin.CAPI.STB.Sign.STB34101
{
    ///////////////////////////////////////////////////////////////////////
    // Алгоритм проверки подписи СТБ 34.101
    ///////////////////////////////////////////////////////////////////////
    public class VerifyHash : CAPI.VerifyHash
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // алгоритм хэширования
        private CAPI.Hash hashAlgorithm; 
    
        // конструктор
        public VerifyHash(CAPI.Hash hashAlgorithm) 
        { 
            // сохранить переданные параметры
            this.hashAlgorithm = RefObject.AddRef(hashAlgorithm); 
        }
        // освободить используемые ресурсы
        protected override void OnDispose()
        {
            // освободить используемые ресурсы
            RefObject.Release(hashAlgorithm); base.OnDispose();
        }
        public override void Verify(IPublicKey publicKey, 
            ASN1.ISO.AlgorithmIdentifier hashParameters, byte[] hash, byte[] signature)
        {
            // преобразовать тип ключа
            STB.STB34101.IPublicKey stbPublicKey = 
                (STB.STB34101.IPublicKey)publicKey;

            // получить параметры алгоритма
            STB.STB34101.IParameters parameters = 
                (STB.STB34101.IParameters)publicKey.Parameters; 

            // создать эллиптическую кривую
            EC.Curve ec = parameters.Curve; 

            // извлечь параметры алгоритма
            Math.BigInteger q = parameters.Order; int bitsQ = q.BitLength;

            // указать поле для вычислений
            Math.Fp.Field field = new Math.Fp.Field(q);
        
            // создать экспоненту
            Math.BigInteger H = Math.Convert.ToBigInteger(hash, Endian).Mod(q);  

            // создать базовую точку эллиптической кривой
            EC.Point G = parameters.Generator; EC.Point Q = stbPublicKey.Q;
        
            // проверить размер подписи
            int len = signature.Length; if (len != 3 * (bitsQ / 16))
            {
                // при ошибке выбросить исключение
                throw new SignatureException(); 
            }
            // выделить память для закодированных значений S0 и S1
            byte[] encodedS0 = new byte[1 + len / 3]; 
            byte[] encodedS1 = new byte[2 * len / 3];

            // извлечь закодированные значения S и R
            Array.Copy(signature,       0, encodedS0, 0,     len / 3);
            Array.Copy(signature, len / 3, encodedS1, 0, 2 * len / 3);
        
            // выполнить сложение S0 и 2^l
            encodedS0[len / 3] = 1; 
        
            // раскодировать большие числа
            Math.BigInteger S0 = Math.Convert.ToBigInteger(encodedS0, Endian);
            Math.BigInteger S1 = Math.Convert.ToBigInteger(encodedS1, Endian); 
        
            // проверить значение S1
            if (S1.CompareTo(q) >= 0) throw new SignatureException();
        
            // вычислить (S1 + H) mod q
            S1 = field.Add(S1, H); 
        
            // вычислить кратную точку
            EC.Point R = ec.MultiplySum(G, S1, Q, S0); 
        
            // проверить значение кратной точки
            if (Object.ReferenceEquals(R, Math.Point<Math.BigInteger>.Infinity)) throw new SignatureException();
        
            // закодировать значение кратной точки
            byte[] encodedR = Math.Convert.FromBigInteger(R.X, Endian, bitsQ / 8); 

            // создать буфер для хэширования
            hash = Arrays.Concat(hashParameters.Algorithm.Encoded, encodedR, hash); 
        
            // выполнить хэширование
            hash = hashAlgorithm.HashData(hash, 0, hash.Length); 
        
            // сравнить хэш-значения
            if (!Arrays.Equals(encodedS0, 0, hash, 0, len / 3))
            {
                // при ошибке выбросить исключение
                throw new SignatureException(); 
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        protected static void KnownTest(CAPI.VerifyHash verifyHash, 
            CAPI.Hash hbelt, string paramOID, Math.BigInteger d, byte[] M, byte[] signature)
        {
            // указать фабрику алгоритмов
            KeyFactory keyFactory = new STB.STB34101.KeyFactory(
                ASN1.STB.OID.stb34101_bign_pubKey
            ); 
            // получить параметры алгоритма
            STB.STB34101.IParameters parameters = 
                (STB.STB34101.IParameters)keyFactory.DecodeParameters(
                    new ASN1.ObjectIdentifier(paramOID)
            );
		    // создать открытый ключ
		    IPublicKey publicKey = new STB.STB34101.PublicKey(
                keyFactory, parameters, 
                parameters.Curve.Multiply(parameters.Generator, d)
            );
            // закодировать параметры алгоритма хэширования
            ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_hash), ASN1.Null.Instance
            ); 
            // вычислить хэш-значение
            byte[] hash = hbelt.HashData(M, 0, M.Length); 

            // проверить подпись хэш-значения
            KnownTest(verifyHash, publicKey, hashParameters, hash, signature); 
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование алгоритма
        ////////////////////////////////////////////////////////////////////////////
        public static void Test(CAPI.VerifyHash verifyHash, CAPI.Hash hbelt)
        {
            KnownTest(verifyHash, hbelt, ASN1.STB.OID.stb34101_bign_curve256_v1, 
                new Math.BigInteger(1, new byte[] {
                (byte)0x69, (byte)0xE2, (byte)0x73, (byte)0xC2, 
                (byte)0x5F, (byte)0x23, (byte)0x79, (byte)0x0C, 
                (byte)0x9E, (byte)0x42, (byte)0x32, (byte)0x07, 
                (byte)0xED, (byte)0x1F, (byte)0x28, (byte)0x34, 
                (byte)0x18, (byte)0xF2, (byte)0x74, (byte)0x9C, 
                (byte)0x32, (byte)0xF0, (byte)0x33, (byte)0x45, 
                (byte)0x67, (byte)0x39, (byte)0x73, (byte)0x4B, 
                (byte)0xB8, (byte)0xB5, (byte)0x66, (byte)0x1F 
            }), new byte[] {
                (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
                (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
                (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
                (byte)0x58 
            }, new byte[] {
                (byte)0xE3, (byte)0x6B, (byte)0x7F, (byte)0x03, 
                (byte)0x77, (byte)0xAE, (byte)0x4C, (byte)0x52, 
                (byte)0x40, (byte)0x27, (byte)0xC3, (byte)0x87, 
                (byte)0xFA, (byte)0xDF, (byte)0x1B, (byte)0x20, 
                (byte)0xCE, (byte)0x72, (byte)0xF1, (byte)0x53, 
                (byte)0x0B, (byte)0x71, (byte)0xF2, (byte)0xB5, 
                (byte)0xFD, (byte)0x3A, (byte)0x8C, (byte)0x58, 
                (byte)0x4F, (byte)0xE2, (byte)0xE1, (byte)0xAE,
                (byte)0xD2, (byte)0x00, (byte)0x82, (byte)0xE3, 
                (byte)0x0C, (byte)0x8A, (byte)0xF6, (byte)0x50, 
                (byte)0x11, (byte)0xF4, (byte)0xFB, (byte)0x54, 
                (byte)0x64, (byte)0x9D, (byte)0xFD, (byte)0x3D            
            }); 
            KnownTest(verifyHash, hbelt, ASN1.STB.OID.stb34101_bign_curve256_v1, 
                new Math.BigInteger(1, new byte[] {
                (byte)0x69, (byte)0xE2, (byte)0x73, (byte)0xC2, 
                (byte)0x5F, (byte)0x23, (byte)0x79, (byte)0x0C, 
                (byte)0x9E, (byte)0x42, (byte)0x32, (byte)0x07, 
                (byte)0xED, (byte)0x1F, (byte)0x28, (byte)0x34, 
                (byte)0x18, (byte)0xF2, (byte)0x74, (byte)0x9C, 
                (byte)0x32, (byte)0xF0, (byte)0x33, (byte)0x45, 
                (byte)0x67, (byte)0x39, (byte)0x73, (byte)0x4B, 
                (byte)0xB8, (byte)0xB5, (byte)0x66, (byte)0x1F 
            }), new byte[] {
                (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
                (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
                (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
                (byte)0x58, (byte)0x4A, (byte)0x5D, (byte)0xE4, 
                (byte)0x85, (byte)0x04, (byte)0xFA, (byte)0x9D, 
                (byte)0x1B, (byte)0xB6, (byte)0xC7, (byte)0xAC, 
                (byte)0x25, (byte)0x2E, (byte)0x72, (byte)0xC2, 
                (byte)0x02, (byte)0xFD, (byte)0xCE, (byte)0x0D, 
                (byte)0x5B, (byte)0xE3, (byte)0xD6, (byte)0x12, 
                (byte)0x17, (byte)0xB9, (byte)0x61, (byte)0x81, 
                (byte)0xFE, (byte)0x67, (byte)0x86, (byte)0xAD, 
                (byte)0x71, (byte)0x6B, (byte)0x89, (byte)0x0B
            }, new byte[] {
                (byte)0x47, (byte)0xA6, (byte)0x3C, (byte)0x8B, 
                (byte)0x9C, (byte)0x93, (byte)0x6E, (byte)0x94, 
                (byte)0xB5, (byte)0xFA, (byte)0xB3, (byte)0xD9, 
                (byte)0xCB, (byte)0xD7, (byte)0x83, (byte)0x66, 
                (byte)0x29, (byte)0x0F, (byte)0x32, (byte)0x10, 
                (byte)0xE1, (byte)0x63, (byte)0xEE, (byte)0xC8, 
                (byte)0xDB, (byte)0x4E, (byte)0x92, (byte)0x1E, 
                (byte)0x84, (byte)0x79, (byte)0xD4, (byte)0x13, 
                (byte)0x8F, (byte)0x11, (byte)0x2C, (byte)0xC2, 
                (byte)0x3E, (byte)0x6D, (byte)0xCE, (byte)0x65, 
                (byte)0xEC, (byte)0x5F, (byte)0xF2, (byte)0x1D, 
                (byte)0xF4, (byte)0x23, (byte)0x1C, (byte)0x28
            }); 
        }
    }
}

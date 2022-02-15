using System;

///////////////////////////////////////////////////////////////////////
// Алгоритм подписи СТБ 34.101
///////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.Sign.STB34101
{
    public class SignHash : CAPI.SignHash
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // алгоритм хэширования
        private CAPI.Hash hashAlgorithm; 
    
        // конструктор
        public SignHash(CAPI.Hash hashAlgorithm) 
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
        public override byte[] Sign(IPrivateKey privateKey, IRand rand, 
            ASN1.ISO.AlgorithmIdentifier hashParameters, byte[] hash)
        {
            // преобразовать тип ключа
            STB.STB34101.IPrivateKey stbPrivateKey = 
                (STB.STB34101.IPrivateKey)privateKey;

            // получить параметры алгоритма
            STB.STB34101.IParameters parameters = 
                (STB.STB34101.IParameters)privateKey.Parameters; 

            // создать эллиптическую кривую
            EC.Curve ec = parameters.Curve; EC.Point G = parameters.Generator;

            // извлечь параметры алгоритма
            Math.BigInteger q = parameters.Order; int bitsQ = q.BitLength;

            // указать поле для вычислений
            Math.Fp.Field field = new Math.Fp.Field(q);
        
            // создать экспоненту
            Math.BigInteger H = Math.Convert.ToBigInteger(hash, Endian).Mod(q);  

            // извлечь секретное значение
            Math.BigInteger d = stbPrivateKey.D; Math.BigInteger k = null; 

            // указать генератор случайных чисел
            using (Random random = new Random(rand))
            do {             
                // сгенерировать ненулевое число
                k = new Math.BigInteger(bitsQ, random); 
            } 
            // проверить выполнение условий
            while (k.Signum == 0); 

            // выполнить вычисления
            byte[] encodedR = Math.Convert.FromBigInteger(ec.Multiply(G, k).X, Endian, bitsQ / 8); 

            // создать буфер для хэширования
            hash = Arrays.Concat(hashParameters.Algorithm.Encoded, encodedR, hash); 
        
            // выполнить хэширование
            hash = hashAlgorithm.HashData(hash, 0, hash.Length); 
        
            // закодировать данные
            byte[] S0 = Arrays.CopyOf(hash, 0, bitsQ / 16); 
        
            // вычислить S0 + 2^l
            Math.BigInteger S01 = Math.Convert.ToBigInteger(Arrays.Concat(S0, new byte[] { 1 }), Endian); 
        
            // выполнить вычисления
            Math.BigInteger S1 = field.Subtract(field.Subtract(k, H), field.Product(S01, d)); 
        
            // вернуть значение подписи
            return Arrays.Concat(S0, Math.Convert.FromBigInteger(S1, Endian, bitsQ / 8)); 
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        protected static void KnownTest(CAPI.Factory factory, SecurityObject scope, 
            CAPI.SignHash signHash, CAPI.Hash hbelt, string paramOID, 
            Math.BigInteger d, byte[] k, byte[] M, byte[] signature) 
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
            // создать личный ключ
            using (IPrivateKey privateKey = new STB.STB34101.PrivateKey(
                factory, null, keyFactory.KeyOID, parameters, d))
            {
                // закодировать параметры алгоритма хэширования
                ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_hash), ASN1.Null.Instance
                ); 
                // вычислить хэш-значение
                byte[] hash = hbelt.HashData(M, 0, M.Length); 
            
                // выполнить тест
                KnownTest(scope, signHash, publicKey, privateKey, 
                    new byte[][] { k }, hashParameters, hash, signature
                ); 
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование алгоритма
        ////////////////////////////////////////////////////////////////////////////
        public static void Test(CAPI.Factory factory, SecurityObject scope, 
            CAPI.SignHash signHash, CAPI.Hash hbelt) 
        {
            KnownTest(factory, scope, signHash, hbelt, 
                ASN1.STB.OID.stb34101_bign_curve256_v1, 
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
                (byte)0xD2, (byte)0xB7, (byte)0x08, (byte)0xA3, 
                (byte)0x7A, (byte)0xA7, (byte)0x33, (byte)0x5C, 
                (byte)0xE1, (byte)0x1C, (byte)0x46, (byte)0x3C, 
                (byte)0x48, (byte)0xEC, (byte)0xD6, (byte)0x3E, 
                (byte)0x2C, (byte)0x74, (byte)0xFA, (byte)0xE0, 
                (byte)0xE7, (byte)0x3D, (byte)0xF2, (byte)0x21, 
                (byte)0xAD, (byte)0x11, (byte)0x58, (byte)0xCD, 
                (byte)0xB2, (byte)0x74, (byte)0x0E, (byte)0x4C 
            }, new byte[] {
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
        }
    }
}

using System;

///////////////////////////////////////////////////////////////////////////
// Формирование общего ключа СТБ 34.101
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.Keyx.STB34101
{
    ////////////////////////////////////////////////////////////////////////////
    // Согласование ключа на стороне-отправителе
    ////////////////////////////////////////////////////////////////////////////
    public class TransportKeyWrap : CAPI.TransportKeyWrap
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // алгоритм шифрования ключа
        private KeyWrap keyWrapAlgorithm; 
    
        // конструктор
        public TransportKeyWrap(KeyWrap keyWrapAlgorithm) 
        {  
            // сохранить переданные параметры
            this.keyWrapAlgorithm = RefObject.AddRef(keyWrapAlgorithm); 
        } 
        // освободить используемые ресурсы
        protected override void OnDispose() 
        {
            // освободить используемые ресурсы
            RefObject.Release(keyWrapAlgorithm); base.OnDispose();
        }
        // зашифровать ключ
        public override TransportKeyData Wrap(
            ASN1.ISO.AlgorithmIdentifier algorithmParameters, 
            IPublicKey publicKey, IRand rand, ISecretKey CEK)
        {
            // преобразовать тип ключа
            STB.STB34101.IPublicKey stbPublicKey = 
                (STB.STB34101.IPublicKey)publicKey;

            // преобразовать тип параметров
            STB.STB34101.IParameters parameters = 
                (STB.STB34101.IParameters)publicKey.Parameters; 
        
            // создать эллиптическую кривую
            EC.Curve ec = parameters.Curve; Math.BigInteger k = null;

            // извлечь параметры алгоритма
            Math.BigInteger q = parameters.Order; int bitsQ = q.BitLength;
        
            // создать базовую точку эллиптической кривой
            EC.Point G = parameters.Generator; EC.Point Q = stbPublicKey.Q;

            // указать генератор случайных чисел
            using (Random random = new Random(rand))
            do {
                // сгенерировать ненулевое число
                k = new Math.BigInteger(bitsQ, random); 
            }
            // проверить выполнение условий
            while (k.Signum == 0); 

            // выполнить вычисления
            byte[] R = Math.Convert.FromBigInteger(ec.Multiply(G, k).X, Endian, bitsQ / 8); 
        
            // выполнить вычисления
            byte[] Theta = Math.Convert.FromBigInteger(ec.Multiply(Q, k).X, Endian, bitsQ / 8);

            // создать ключ шифрования ключа
            using (ISecretKey KEK = keyWrapAlgorithm.KeyFactory.Create(Arrays.CopyOf(Theta, 0, 32)))
            { 
                // зашифровать ключ
                byte[] encryptedKey = Arrays.Concat(R, keyWrapAlgorithm.Wrap(rand, KEK, CEK)); 
        
                // вернуть зашифрованный ключ
                return new TransportKeyData(algorithmParameters, encryptedKey); 
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        protected static void KnownTest(CAPI.TransportKeyWrap transportKeyWrap, 
            string paramOID,  Math.BigInteger d, byte[] k, byte[] I, byte[] CEK, byte[] result) 
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
            // указать случайные данные
            byte[][] random = new byte[][] { k, I }; 
        
            // указать используемые параметры
            ASN1.ISO.AlgorithmIdentifier algorithmParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_bign_keyTransport), ASN1.Null.Instance
            ); 
            // выполнить тест
            KnownTest(transportKeyWrap, algorithmParameters, publicKey, random, CEK, result); 
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование алгоритма
        ////////////////////////////////////////////////////////////////////////////
        public static void Test(CAPI.TransportKeyWrap transportKeyWrap)
        {
            KnownTest(transportKeyWrap, ASN1.STB.OID.stb34101_bign_curve256_v1, 
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
                (byte)0xD5, (byte)0xAA, (byte)0x88, (byte)0x1C,
                (byte)0x6F, (byte)0x8E, (byte)0x1B, (byte)0xBE, 
                (byte)0x2F, (byte)0xD4, (byte)0xA3, (byte)0xF9, 
                (byte)0xA8, (byte)0x62, (byte)0x13, (byte)0xAD, 
                (byte)0xA1, (byte)0x26, (byte)0x4F, (byte)0xEF, 
                (byte)0x7A, (byte)0xB0, (byte)0x4A, (byte)0xBD, 
                (byte)0x20, (byte)0x7C, (byte)0x61, (byte)0x47, 
                (byte)0x13, (byte)0xD9, (byte)0x51, (byte)0x0F 
            }, new byte[] {
                (byte)0x5B, (byte)0xE3, (byte)0xD6, (byte)0x12, 
                (byte)0x17, (byte)0xB9, (byte)0x61, (byte)0x81, 
                (byte)0xFE, (byte)0x67, (byte)0x86, (byte)0xAD, 
                (byte)0x71, (byte)0x6B, (byte)0x89, (byte)0x0B
            }, new byte[] {
                (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
                (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
                (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
                (byte)0x58, (byte)0x4A, (byte)0x5D, (byte)0xE4, 
                (byte)0x85, (byte)0x04
            }, new byte[] {
                (byte)0x9B, (byte)0x4E, (byte)0xA6, (byte)0x69, 
                (byte)0xDA, (byte)0xBD, (byte)0xF1, (byte)0x00, 
                (byte)0xA7, (byte)0xD4, (byte)0xB6, (byte)0xE6, 
                (byte)0xEB, (byte)0x76, (byte)0xEE, (byte)0x52, 
                (byte)0x51, (byte)0x91, (byte)0x25, (byte)0x31, 
                (byte)0xF4, (byte)0x26, (byte)0x75, (byte)0x0A, 
                (byte)0xAC, (byte)0x8A, (byte)0x9D, (byte)0xBB, 
                (byte)0x51, (byte)0xC5, (byte)0x4D, (byte)0x8D, 
                (byte)0xEB, (byte)0x92, (byte)0x89, (byte)0xB5, 
                (byte)0x0A, (byte)0x46, (byte)0x95, (byte)0x2D, 
                (byte)0x05, (byte)0x31, (byte)0x86, (byte)0x1E, 
                (byte)0x45, (byte)0xA8, (byte)0x81, (byte)0x4B, 
                (byte)0x00, (byte)0x8F, (byte)0xDC, (byte)0x65, 
                (byte)0xDE, (byte)0x9F, (byte)0xF1, (byte)0xFA, 
                (byte)0x2A, (byte)0x1F, (byte)0x16, (byte)0xB6, 
                (byte)0xA2, (byte)0x80, (byte)0xE9, (byte)0x57, 
                (byte)0xA8, (byte)0x14
            }); 
        }
    }
}


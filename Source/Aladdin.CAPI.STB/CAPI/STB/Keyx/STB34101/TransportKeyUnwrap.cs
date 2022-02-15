using System;
using System.IO;

namespace Aladdin.CAPI.STB.Keyx.STB34101
{
    ////////////////////////////////////////////////////////////////////////////
    // Согласование ключа на стороне-получателе
    ////////////////////////////////////////////////////////////////////////////
    public class TransportKeyUnwrap : CAPI.TransportKeyUnwrap
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // алгоритм шифрования ключа
        private KeyWrap keyWrapAlgorithm; 
    
        // конструктор
        public TransportKeyUnwrap(KeyWrap keyWrapAlgorithm) 
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
        public override ISecretKey Unwrap(IPrivateKey privateKey, 
            TransportKeyData transportData, SecretKeyFactory keyFactory) 
        {
            // преобразовать тип ключа
            STB.STB34101.IPrivateKey stbPrivateKey = 
                (STB.STB34101.IPrivateKey)privateKey; 
        
            // преобразовать тип параметров
            STB.STB34101.IParameters parameters = 
                (STB.STB34101.IParameters)privateKey.Parameters; 
        
            // создать эллиптическую кривую
            EC.CurveFp ec = parameters.Curve; EC.FieldFp field = ec.Field;
            
            // извлечь параметры алгоритма
            Math.BigInteger q = parameters.Order; int bitsQ = q.BitLength;
        
            // извлечь секретное значение
            Math.BigInteger d = stbPrivateKey.D; byte[] encryptedKey = transportData.EncryptedKey; 
        
            // проверить размер зашифрованного ключа
            if (encryptedKey.Length < bitsQ / 8 + 32) throw new InvalidDataException(); 
        
            // раскодировать значение xR
            Math.BigInteger xR = Math.Convert.ToBigInteger(encryptedKey, 0, bitsQ / 8, Endian); 
        
            // проверить корректность значения xR
            if (xR.CompareTo(field.P) >= 0) throw new InvalidDataException(); 
        
            // вычислить xR^3 + axR + b
            Math.BigInteger check = field.Add(ec.B, field.Product(xR, field.Add(ec.A, field.Sqr(xR)))); 
        
            // вычислить (p + 1) / 4
            Math.BigInteger exponent = field.P.Add(Math.BigInteger.One).ShiftRight(2); 
        
            // выполнить возведение в степень
            Math.BigInteger yR = field.Power(check, exponent);  
        
            // проверить коррректность данных
            if (field.Sqr(yR).CompareTo(check) != 0) throw new InvalidDataException(); 
        
            // построить точку эллиптической кривой
            EC.Point R = new EC.Point(xR, yR); R = ec.Multiply(R, d); 
        
            // выполнить вычисления
            byte[] Theta = Math.Convert.FromBigInteger(R.X, Endian, bitsQ / 8); 

            // извлечь зашифрованный ключ
            encryptedKey = Arrays.CopyOf(encryptedKey, bitsQ / 8, encryptedKey.Length - bitsQ / 8); 
        
            // создать ключ шифрования ключа
            using(ISecretKey KEK = keyWrapAlgorithm.KeyFactory.Create(Arrays.CopyOf(Theta, 0, 32)))
            { 
                // расшифровать ключ
                return keyWrapAlgorithm.Unwrap(KEK, encryptedKey, keyFactory);  
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        private static void KnownTest(CAPI.Factory factory, SecurityObject scope, 
            CAPI.TransportKeyUnwrap transportKeyUnwrap, string paramOID, 
            Math.BigInteger d, byte[] CEK, byte[] result) 
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
                // указать параметры алгоритма
                ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_belt_keyWrap_256), ASN1.Null.Instance
                );
                // закодировать параметры алгоритма 
                ASN1.ISO.AlgorithmIdentifier algParameters = new ASN1.ISO.AlgorithmIdentifier(
                    new ASN1.ObjectIdentifier(ASN1.STB.OID.stb34101_bign_keyTransport), 
                    wrapParameters
                );
                // указать значение для проверки
                TransportKeyData check = new TransportKeyData(algParameters, result); 
            
                // выполнить тест
                KnownTest(scope, transportKeyUnwrap, publicKey, privateKey, CEK, check); 
            }
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тестирование алгоритма
        ////////////////////////////////////////////////////////////////////////////
        public static void Test(CAPI.Factory factory, SecurityObject scope, 
            CAPI.TransportKeyUnwrap transportKeyUnwrap) 
        {
            KnownTest(factory, scope, transportKeyUnwrap, 
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
            KnownTest(factory, scope, transportKeyUnwrap, 
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
                (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
                (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
                (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
                (byte)0x58, (byte)0x4A, (byte)0x5D, (byte)0xE4, 
                (byte)0x85, (byte)0x04, (byte)0xFA, (byte)0x9D, 
                (byte)0x1B, (byte)0xB6, (byte)0xC7, (byte)0xAC, 
                (byte)0x25, (byte)0x2E, (byte)0x72, (byte)0xC2, 
                (byte)0x02, (byte)0xFD, (byte)0xCE, (byte)0x0D
            }, new byte[] {
                (byte)0x48, (byte)0x56, (byte)0x09, (byte)0x3A, 
                (byte)0x0F, (byte)0x6C, (byte)0x13, (byte)0x01, 
                (byte)0x5F, (byte)0xC8, (byte)0xE1, (byte)0x5F, 
                (byte)0x1B, (byte)0x23, (byte)0xA7, (byte)0x62, 
                (byte)0x02, (byte)0xD2, (byte)0xF4, (byte)0xBA, 
                (byte)0x6E, (byte)0x5E, (byte)0xC5, (byte)0x2B, 
                (byte)0x78, (byte)0x65, (byte)0x84, (byte)0x77, 
                (byte)0xF6, (byte)0x48, (byte)0x6D, (byte)0xE6, 
                (byte)0x87, (byte)0xAF, (byte)0xAE, (byte)0xEA, 
                (byte)0x0E, (byte)0xF7, (byte)0xBC, (byte)0x13, 
                (byte)0x26, (byte)0xA7, (byte)0xDC, (byte)0xE7, 
                (byte)0xA1, (byte)0x0B, (byte)0xA1, (byte)0x0E, 
                (byte)0x3F, (byte)0x91, (byte)0xC0, (byte)0x12, 
                (byte)0x60, (byte)0x44, (byte)0xB2, (byte)0x22, 
                (byte)0x67, (byte)0xBF, (byte)0x30, (byte)0xBD, 
                (byte)0x6F, (byte)0x1D, (byte)0xA2, (byte)0x9E, 
                (byte)0x06, (byte)0x47, (byte)0xCF, (byte)0x39, 
                (byte)0xC1, (byte)0xD5, (byte)0x9A, (byte)0x56, 
                (byte)0xBB, (byte)0x01, (byte)0x94, (byte)0xE0, 
                (byte)0xF4, (byte)0xF8, (byte)0xA2, (byte)0xBB
            }); 
        }   
    }
}

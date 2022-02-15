using System;

namespace Aladdin.CAPI.GOST.Keyx.GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////////
    // Формирование общего ключа ГОСТ Р 34.10-1994
    ///////////////////////////////////////////////////////////////////////////
    public class DHKeyAgreement : CAPI.KeyAgreement
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // алгоритм наследования ключа
        private KeyDerive keyDerive; 

        // конструктор
        public DHKeyAgreement(KeyDerive keyDerive)
        {
            // сохранить переданные параметры
            this.keyDerive = RefObject.AddRef(keyDerive); 
        }
        // конструктор
        public DHKeyAgreement()
        { 
            // указать алгоритм наследования ключа
            this.keyDerive = new CAPI.Derive.NOKDF(Endian); 
        } 
        // деструктор
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(keyDerive); base.OnDispose();
        }
        // сгенерировать случайные данные
	    public override byte[] Generate(IParameters parameters, IRand rand) 
        { 
            // сгенерировать случайные данные
            byte[] random = new byte[8]; rand.Generate(random, 0, random.Length);

            // проверить наличие ненулевых байтов
            if (random[0] == 0) random[0] ^= 0x1; return random;  
        }
        // наследовать ключ
        public override ISecretKey DeriveKey(IPrivateKey privateKey, 
            IPublicKey publicKey, byte[] random, SecretKeyFactory keyFactory, int keySize)
        {
            // преобразовать тип параметров
            CAPI.GOST.GOSTR3410.IDHParameters parameters = 
                (CAPI.GOST.GOSTR3410.IDHParameters) privateKey.Parameters; 

            // преобразовать тип данных
            CAPI.GOST.GOSTR3410.IDHPrivateKey privateKeyX = 
                (CAPI.GOST.GOSTR3410.IDHPrivateKey)privateKey; 
            CAPI.GOST.GOSTR3410.IDHPublicKey publicKeyX = 
                (CAPI.GOST.GOSTR3410.IDHPublicKey)publicKey;

            // извлечь параметры алгоритма
            Math.BigInteger p = parameters.P; Math.BigInteger y = publicKeyX.Y;

            // выполнить математические операции
            Math.BigInteger k = y.ModPow(privateKeyX.X, p);
        
            // выделить память для точки эллиптической кривой
            byte[] encodedK = new byte[(p.BitLength + 7) / 8];  
        
            // закодировать координаты точки
            Math.Convert.FromBigInteger(k, Endian, encodedK, 0, encodedK.Length); 

            // создать алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = CreateHashAlgorithm(privateKey, keySize))
            {  
                // получить ключ как хэш-значение
                using (ISecretKey key = keyDerive.KeyFactory.Create(
                    hashAlgorithm.HashData(encodedK, 0, encodedK.Length)))
                {
                    // выполнить наследование ключа
                    return keyDerive.DeriveKey(key, random, keyFactory, keySize); 
                }
            } 
        }
        // создать алгоритм хэширования
        protected virtual CAPI.Hash CreateHashAlgorithm(IPrivateKey privateKey, int keySize)
        {
            // преобразовать тип параметров
            GOST.GOSTR3410.INamedParameters parameters = 
                (GOST.GOSTR3410.INamedParameters)privateKey.Parameters; 
        
            // получить именованные параметры алгоритма
            ASN1.GOST.GOSTR3411ParamSet1994 namedParameters = 
                ASN1.GOST.GOSTR3411ParamSet1994.Parameters(parameters.HashOID);

            // раскодировать таблицу подстановок
            byte[] sbox = ASN1.GOST.GOST28147SBoxReference.DecodeSBox(namedParameters.HUZ); 

            // создать алгоритм хэширования
            return new Hash.GOSTR3411_1994(sbox, namedParameters.H0.Value, false);
        }
    }
}
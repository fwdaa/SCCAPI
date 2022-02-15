using System;

namespace Aladdin.CAPI.GOST.Keyx.GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////////
    // Формирование общего ключа ГОСТ Р 34.10-2001, 2012
    ///////////////////////////////////////////////////////////////////////////
    public abstract class ECKeyAgreement : CAPI.KeyAgreement
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // алгоритм наследования ключа
        private KeyDerive keyDerive;
    
        // конструктор
        protected ECKeyAgreement(KeyDerive keyDerive)
        {
            // сохранить переданные параметры
            this.keyDerive = RefObject.AddRef(keyDerive); 
        }
        // конструктор
        protected ECKeyAgreement()
        { 
            // сохранить переданные параметры
            this.keyDerive = new CAPI.Derive.NOKDF(Endian); 
        } 
        // деструктор
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(keyDerive); base.OnDispose();
        }
        // размер случайных данных
        protected virtual int RandomSize { get { return 8; }}

        // сгенерировать случайные данные
	    public override byte[] Generate(IParameters parameters, IRand rand)
	    {
            // сгенерировать случайные данные
            byte[] random = new byte[RandomSize]; rand.Generate(random, 0, random.Length);

            // для случайных данных
            bool zero = true; for (int i = 0; i < random.Length; i++)
            {
                // проверить отсутствие нулевых данных
                if (random[i] != 0) { zero = false; break; }
            }
            // скорректировать нулевые данные
            if (zero) random[0] = 0x1; return random;  
        }
        // наследовать ключ
	    public override ISecretKey DeriveKey(IPrivateKey privateKey, 
            IPublicKey publicKey, byte[] random, SecretKeyFactory keyFactory, int keySize)
	    {
            // преобразовать тип параметров
	        CAPI.GOST.GOSTR3410.IECParameters parameters = 
                (CAPI.GOST.GOSTR3410.IECParameters) privateKey.Parameters; 

	        // преобразовать тип данных
	        CAPI.GOST.GOSTR3410.IECPrivateKey privateKeyX = 
                (CAPI.GOST.GOSTR3410.IECPrivateKey)privateKey; 
	        CAPI.GOST.GOSTR3410.IECPublicKey publicKeyX = 
                (CAPI.GOST.GOSTR3410.IECPublicKey )publicKey;
 
            // извлечь параметры алгоритма
            EC.Curve ec = parameters.Curve; Math.BigInteger q = parameters.Order;

            // создать большое число по случайным данным
            Math.BigInteger ukm = Math.Convert.ToBigInteger(random, Endian); 

            // выполнить математические операции
            EC.Point point = ec.Multiply(publicKeyX.Q, privateKeyX.D.Multiply(ukm).Mod(q));

            // выделить память для точки эллиптической кривой
            byte[] xy = new byte[(q.BitLength + 7) / 8 * 2];  
        
            // закодировать координаты точки
            Math.Convert.FromBigInteger(point.X, Endian, xy,             0, xy.Length / 2); 
            Math.Convert.FromBigInteger(point.Y, Endian, xy, xy.Length / 2, xy.Length / 2);

            // создать алгоритм хэширования
	        using (CAPI.Hash hashAlgorithm = CreateHashAlgorithm(privateKey, keySize))
            { 
                // получить ключ как хэш-значение
                using (ISecretKey key = keyDerive.KeyFactory.Create(
                    hashAlgorithm.HashData(xy, 0, xy.Length)))
                {
                    // выполнить наследование ключа
                    return keyDerive.DeriveKey(key, random, keyFactory, keySize); 
                }
            }
	    }
        // создать алгоритм хэширования
        protected abstract CAPI.Hash CreateHashAlgorithm(IPrivateKey privateKey, int keySize); 
    }
}
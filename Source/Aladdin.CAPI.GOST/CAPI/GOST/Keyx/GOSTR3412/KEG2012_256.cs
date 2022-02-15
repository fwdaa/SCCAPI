using System;
using System.IO;
using System.Text;

namespace Aladdin.CAPI.GOST.Keyx.GOSTR3412
{
    ///////////////////////////////////////////////////////////////////////////
    // Формирование общего ключа KEG (личный ключ 32 байта)
    ///////////////////////////////////////////////////////////////////////////
    public class KEG2012_256 : GOSTR3410.ECKeyAgreement2012 
    {
        // алгоритм HMAC и синхропосылка
        private Mac hmac_gostr3411_2012_256; 
    
        // конструктор
        public KEG2012_256(Mac hmac_gostr3411_2012_256)
        {
            // сохранить переданные параметры
            this.hmac_gostr3411_2012_256 = RefObject.AddRef(hmac_gostr3411_2012_256); 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            RefObject.Release(hmac_gostr3411_2012_256); base.Dispose();         
        } 
        // размер случайных данных
        protected override int RandomSize { get { return 32; }}

        // сгенерировать случайные данные
        public override byte[] Generate(IParameters parameters, IRand rand)
        {
            // выделить буфер для случайных данных
            byte[] random = new byte[RandomSize]; 
            
            // сгенерировать случайные данные
            rand.Generate(random, 0, random.Length); return random; 
        }
 	    // согласовать общий ключ на стороне получателя
	    public override ISecretKey DeriveKey(IPrivateKey privateKey, 
            IPublicKey publicKey, byte[] random, SecretKeyFactory keyFactory, int keySize)
        {
            // проверить указание размера
            if (keySize < 0) keySize = 64; if (keySize != 64) throw new InvalidDataException();
        
            // скопировать часть случайных данных
            byte[] r = new byte[16]; Array.Copy(random, 0, r, 0, r.Length);
        
            // для случайных данных
            bool zero = true; for (int i = 0; i < r.Length; i++)
            {
                // проверить отсутствие нулевых данных
                if (random[i] != 0) { zero = false; break; }
            }
            // скорректировать нулевые данные
            Array.Reverse(r); if (zero) r[0] = 0x1; 
        
            // преобразовать тип параметров
            GOST.GOSTR3410.IECParameters parameters = 
                (GOST.GOSTR3410.IECParameters) privateKey.Parameters; 
        
            // определить размер личного ключа
            int privateKeyLength = (parameters.Order.BitLength + 7) / 8; 

            // проверить корректность размера
            if (privateKeyLength != keySize / 2) throw new InvalidDataException();
             
            // указать фабрику создания ключа
            SecretKeyFactory genericKeyFactory = SecretKeyFactory.Generic; 
            
            // согласовать общий ключ
            using (ISecretKey key = base.DeriveKey(privateKey, publicKey, r, genericKeyFactory, keySize / 2))
            {
                // создать алгоритм наследования ключа
                using (KeyDerive keyDerive = CreateKDF_TREE(Encoding.ASCII.GetBytes("kdf tree"), 1))
                {
                    // извлечь значение синхропосылки
                    byte[] seed = new byte[8]; Array.Copy(random, 16, seed, 0, seed.Length);
        
                    // увеличить размер ключа
                    return keyDerive.DeriveKey(key, seed, keyFactory, keySize); 
                }
            }
        }
        // создать алгоритм наследования
        protected virtual KeyDerive CreateKDF_TREE(byte[] label, int R) 
        { 
            // создать алгоритм наследования
            if (hmac_gostr3411_2012_256 != null) return new CAPI.Derive.TREEKDF(hmac_gostr3411_2012_256, label, R); 
        
            // создать алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = new Hash.GOSTR3411_2012(256))
            {
                // создать алгоритм вычисления имитовставки
                using (Mac macAlgorithm = new CAPI.MAC.HMAC(hashAlgorithm))
                {
                    // создать алгоритм наследования
                    return new CAPI.Derive.TREEKDF(macAlgorithm, label, R); 
                }
            }
        }
    }
}

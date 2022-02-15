using System;

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////////
    // Тип ключа шифрования
    ///////////////////////////////////////////////////////////////////////////////
    public class SecretKeyFactory 
    {
        // произвольный ключ
        public static readonly SecretKeyFactory Generic = new SecretKeyFactory();

        // конструктор
        protected SecretKeyFactory() {}
    
        // размер ключей
        public virtual int[] KeySizes { get { return CAPI.KeySizes.Unrestricted; }} 

        // создать ключ
        public virtual ISecretKey Create(byte[] value) 
        { 
            // проверить размер ключа
            if (!CAPI.KeySizes.Contains(KeySizes, value.Length)) 
            {
                // при ошибке выбросить исключение
                throw new NotSupportedException();
            } 
            // создать ключ
            return new SecretKey(this, value); 
        }
        // сгенерировать ключ
        public virtual ISecretKey Generate(IRand rand, int keySize) 
        {
            // проверить размер ключа
            if (!CAPI.KeySizes.Contains(KeySizes, keySize)) 
            {
                // при ошибке выбросить исключение
                throw new NotSupportedException();
            } 
            // сгенерировать ключ
            byte[] value = new byte[keySize]; rand.Generate(value, 0, keySize);
        
            // вернуть сгенерированный ключ
            return new SecretKey(this, value); 
        }
    }
}

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
        public SecretKeyFactory() : this(CAPI.KeySizes.Unrestricted) {}
        
        // конструктор
        public SecretKeyFactory(int[] keySizes) 
        
            // сохранить переданные параметры
            { this.keySizes = keySizes; } private int[] keySizes; 
        
        // ограничить допустимые ключи
        public virtual SecretKeyFactory Narrow(int[] keySizes)
        {
            // при допустимости только одного размера ключа
            if (this.keySizes != null && this.keySizes.Length == 1)
            {
                // проверить корректность действий
                if (keySizes == null || keySizes.Length != 1)
                {
                    // при ошибке выбросить исключение
                    throw new ArgumentException(); 
                }
                // проверить совпадение размера ключа
                if (keySizes[0] != this.keySizes[0]) 
                {
                    // при ошибке выбросить исключение
                    throw new ArgumentException(); 
                }
                return this; 
            }
            // ограничить допустимые ключи
            return new SecretKeyFactory(keySizes); 
        }
        // размер ключей
        public int[] KeySizes { get { return keySizes; }}

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

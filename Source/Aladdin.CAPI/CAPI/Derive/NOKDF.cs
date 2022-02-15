using System; 

namespace Aladdin.CAPI.Derive
{
    ///////////////////////////////////////////////////////////////////////////////
    // Отсутствие наследования ключа
    ///////////////////////////////////////////////////////////////////////////////
    public class NOKDF : KeyDerive 
    {
        // конструктор
        public NOKDF(Math.Endian endian) 
    
            // сохранить переданные параметры
            { this.endian = endian; } private Math.Endian endian;
    
	    // наследовать ключ
	    public override ISecretKey DeriveKey(ISecretKey key, 
            byte[] random, SecretKeyFactory keyFactory, int deriveSize)
        {
            // проверить наличие размера
            if (deriveSize < 0) throw new InvalidOperationException();  

            // проверить совпадение размера
            if (key.Length == deriveSize && Object.ReferenceEquals(key.KeyFactory, keyFactory)) 
            {
                // увеличить счетчик ссылок ключа
                return RefObject.AddRef(key);
            }
            // проверить размер ключа
            if (key.Length < deriveSize) throw new InvalidKeyException();
        
            // получить значение ключа
            byte[] value = key.Value; if (value == null) 
            {
                // при ошибке выбросить исключение
                throw new InvalidKeyException();
            } 
            // в зависимости от способа кодирования чисел
            if (endian == Math.Endian.BigEndian) 
            {
                // удалить незначимые байты
                Array.Copy(value, value.Length - deriveSize, value, 0, deriveSize);
            }
            // указать требуемый размер
            Array.Resize(ref value, deriveSize); return keyFactory.Create(value);
        }
    }
}

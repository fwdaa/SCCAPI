package aladdin.capi.derive;
import aladdin.*;
import aladdin.math.*;
import aladdin.capi.*;
import java.io.*;
import java.security.*;
import java.util.Arrays;

///////////////////////////////////////////////////////////////////////////////
// Отсутствие наследования ключа
///////////////////////////////////////////////////////////////////////////////
public class NOKDF extends KeyDerive 
{
    // конструктор
    public NOKDF(Endian endian) 
    
        // сохранить переданные параметры
        { this.endian = endian; } private final Endian endian;
    
	// наследовать ключ
	@Override public ISecretKey deriveKey(ISecretKey key, byte[] random, 
        SecretKeyFactory keyFactory, int deriveSize) 
        throws IOException, InvalidKeyException
    {
        // проверить наличие размера
        if (deriveSize < 0) throw new IllegalStateException();  
        
        // проверить совпадение размера
        if (key.length() == deriveSize && key.keyFactory() == keyFactory) 
        {
            // увеличить счетчик ссылок ключа
            return RefObject.addRef(key);
        }
        // проверить размер ключа
        if (key.length() < deriveSize) throw new InvalidKeyException();
        
        // получить значение ключа
        byte[] value = key.value(); if (value == null) 
        {
            // при ошибке выбросить исключение
            throw new InvalidKeyException();
        } 
        // в зависимости от способа кодирования чисел
        if (endian == Endian.BIG_ENDIAN) 
        {
            // удалить незначимые байты
            System.arraycopy(value, value.length - deriveSize, value, 0, deriveSize);
        }
        // указать требуемый размер
        return keyFactory.create(Arrays.copyOf(value, deriveSize)); 
    }
}

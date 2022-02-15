package aladdin.capi;
import java.security.*;
import java.security.spec.*;
import javax.crypto.spec.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Тип ключа шифрования
///////////////////////////////////////////////////////////////////////////////
public class SecretKeyFactory 
{
    // произвольный ключ
    public final static SecretKeyFactory GENERIC = new SecretKeyFactory(); 
    
    // конструктор
    protected SecretKeyFactory() { this("GENERIC"); }
        
    // конструктор
    protected SecretKeyFactory(String... names) 
    
        // сохранить переданные параметры
        { this.names = names; } private final String[] names; 
        
    // имя типа
    public final String[] names() { return names; }
    
    // размер ключей
    public int[] keySizes () { return KeySizes.UNRESTRICTED; }
    
    // создать ключ
    public ISecretKey create(byte[] value) 
    { 
        // проверить размер ключа
        if (!KeySizes.contains(keySizes(), value.length)) 
        {
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException();
        } 
        // создать ключ
        return new SecretKey(this, value); 
    }
    // сгенерировать ключ
    public ISecretKey generate(IRand rand, int keySize) throws IOException
    {
        // проверить размер ключа
        if (!KeySizes.contains(keySizes(), keySize)) 
        {
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException();
        } 
        // сгенерировать ключ
        byte[] value = new byte[keySize]; rand.generate(value, 0, keySize);
        
        // вернуть сгенерированный ключ
        return new SecretKey(this, value); 
    }
    // извлечь данные ключа
    public KeySpec getSpec(byte[] value, Class<? extends KeySpec> specType)
        throws InvalidKeyException
    {
        // проверить размер ключа
        if (!KeySizes.contains(keySizes(), value.length)) 
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException();
        } 
        // в зависимости от требуемого формата
        if (specType.isAssignableFrom(SecretKeySpec.class))
        {
            // вернуть значение ключа
            return new SecretKeySpec(value, names[0]); 
        }
        return null; 
    }
}

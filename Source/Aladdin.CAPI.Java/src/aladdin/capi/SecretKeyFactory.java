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
    public final static SecretKeyFactory GENERIC = new SecretKeyFactory(KeySizes.UNRESTRICTED); 

    // конструктор
    public SecretKeyFactory(int[] keySizes) 
        
        // сохранить переданные параметры
        { this.keySizes = keySizes; } private final int[] keySizes; 
        
    // ограничить допустимые ключи
    public SecretKeyFactory narrow(int[] keySizes)
    {
        // при допустимости только одного размера ключа
        if (this.keySizes != null && this.keySizes.length == 1)
        {
            // проверить корректность действий
            if (keySizes == null || keySizes.length != 1)
            {
                // при ошибке выбросить исключение
                throw new IllegalStateException(); 
            }
            // проверить совпадение размера ключа
            if (keySizes[0] != this.keySizes[0]) 
            {
                // при ошибке выбросить исключение
                throw new IllegalStateException(); 
            }
            return this; 
        }
        // ограничить допустимые ключи
        return new SecretKeyFactory(keySizes); 
    }
    // размер ключей
    public final int[] keySizes () { return keySizes; }
    
    // создать ключ
    public ISecretKey create(KeySpec keySpec) throws InvalidKeySpecException
    {
        // проверить тип данных
        if (!(keySpec instanceof SecretKeySpec)) throw new InvalidKeySpecException(); 
        
        // получить значение ключа
        byte[] value = ((SecretKeySpec)keySpec).getEncoded(); 
        
        // создать ключ
        if (value == null) throw new InvalidKeySpecException(); return create(value); 
    }
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
    public KeySpec getSpec(String algorithm, byte[] value, 
        Class<? extends KeySpec> specType) throws InvalidKeyException
    {
        // проверить размер ключа
        if (!KeySizes.contains(keySizes(), value.length)) 
        {
            // при ошибке выбросить исключение
            throw new InvalidKeyException();
        } 
        // в зависимости от требуемого формата
        if (specType.isAssignableFrom(SecretKeySpec.class))
        {
            // вернуть значение ключа
            return new SecretKeySpec(value, algorithm); 
        }
        return null; 
    }
}

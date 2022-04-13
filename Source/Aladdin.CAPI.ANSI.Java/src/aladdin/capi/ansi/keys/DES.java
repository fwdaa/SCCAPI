package aladdin.capi.ansi.keys;
import aladdin.capi.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.spec.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Ключ DES
///////////////////////////////////////////////////////////////////////////
public class DES extends SecretKeyFactory
{
    // тип ключа
    public static final SecretKeyFactory INSTANCE = new DES(); 
        
    // конструктор
    public DES() { super(new int[] {8}); }
    
    // создать ключ
    @Override public ISecretKey create(KeySpec keySpec) throws InvalidKeySpecException
    {
        // проверить тип данных
        if (keySpec instanceof DESKeySpec)
        {
            // получить значение ключа
            byte[] value = ((DESKeySpec)keySpec).getKey(); 
            
            // проверить наличие значения 
            if (value == null) throw new InvalidKeySpecException(); 
            
            // созать ключ
            return create(value); 
        }
        // вызвать базовую функцию
        return super.create(keySpec); 
    }
    // создать ключ
    @Override public ISecretKey create(byte[] value) 
    { 
        // создать копию значения
        value = value.clone(); 
            
        // выполнить нормализацию ключа
        DES.adjustParity(value, 0, value.length); 
            
        // создать ключ
        return super.create(value); 
    }
    // сгенерировать ключ
    @Override public ISecretKey generate(IRand rand, int keySize) throws IOException
    {
        // проверить размер ключа
        if (!KeySizes.contains(keySizes(), keySize)) 
        {
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException();
        } 
        // сгенерировать ключ
        byte[] value = new byte[keySize]; rand.generate(value, 0, keySize);

        // выполнить нормализацию ключа
        DES.adjustParity(value, 0, keySize); 
        try { 
            // для слабого ключа
            while(DESKeySpec.isWeak(value, 0)) 
            {
                // сгенерировать ключ
                rand.generate(value, 0, keySize);

                // выполнить нормализацию ключа
                DES.adjustParity(value, 0, keySize); 
            }
        }
        // обработать неожидаемое исключение
        catch (InvalidKeyException e) { throw new RuntimeException(e); }
            
        // вернуть сгенерированный ключ
        return new SecretKey(this, value); 
    }
    // извлечь данные ключа
    @Override public KeySpec getSpec(String algorithm, 
        byte[] value, Class<? extends KeySpec> specType) 
            throws InvalidKeyException
    {
        // в зависимости от типа
        if (specType.isAssignableFrom(DESKeySpec.class))
        {
            // вернуть значение ключа
            return new DESKeySpec(value); 
        }
        // вызвать базовую функцию
        return super.getSpec(algorithm, value, specType); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // нормализация ключа
    ///////////////////////////////////////////////////////////////////////////
    public static void adjustParity(byte[] key, int offset, int length)
    {
        // для всех байтов ключа
        for (int i = 0; i < length; i++)
        {
            // для всех битов
            int ones = 0; for (int j = 0; j < 8; j++)
            {
                // определить число установленных битов
                if ((key[i + offset] & (0x1 << j)) != 0) ones++;
            }
            // число установленных битов должно быть нечетным
            if((ones % 2) == 0) key[i + offset] ^= 0x01;
        }
    } 
}

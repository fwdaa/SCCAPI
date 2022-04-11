package aladdin.capi.ansi.keys;
import aladdin.capi.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.spec.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Ключ TDES
///////////////////////////////////////////////////////////////////////////
public class TDES extends SecretKeyFactory
{
    // конструктор
    public TDES(int[] keySizes) { super(keySizes); }
    // конструктор
    public TDES() { super(new int[] { 16, 24 }); }
    
    // ограничить размер ключей
    @Override public SecretKeyFactory narrow(int[] keySizes) { return new TDES(keySizes); }
    
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
            // для всех частей ключа
            for (int offset = 0; offset < keySize; offset += 8)
            {
                // для слабого ключа
                while(DESKeySpec.isWeak(value, offset)) 
                {
                    // сгенерировать ключ
                    rand.generate(value, offset, 8);

                    // выполнить нормализацию ключа
                    DES.adjustParity(value, offset, 8); 
                }
            }
        }
        // обработать неожидаемое исключение
        catch (InvalidKeyException e) { throw new RuntimeException(e); }

        // вернуть сгенерированный ключ
        return new SecretKey(this, value); 
    }
    // извлечь данные ключа
    @Override public KeySpec getSpec(String algorithm, byte[] value, 
        Class<? extends KeySpec> specType) throws InvalidKeyException
    {
        // в зависимости от типа
        if (specType.isAssignableFrom(DESedeKeySpec.class))
        {
            // вернуть значение ключа
            return new DESedeKeySpec(value); 
        }
        // вызвать базовую функцию
        return super.getSpec(algorithm, value, specType); 
    }
}

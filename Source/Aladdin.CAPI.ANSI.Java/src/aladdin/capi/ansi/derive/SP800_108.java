package aladdin.capi.ansi.derive;
import aladdin.*; 
import aladdin.math.*;
import aladdin.capi.*; 
import aladdin.util.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Наследование ключа SP800-108
///////////////////////////////////////////////////////////////////////////
public class SP800_108 extends KeyDerive
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 

    // алгоритм хэширования
    private final Mac hmacAlgorithm;
    
	// конструктор
	public SP800_108(Mac hmacAlgorithm) 
    { 
        // сохранить переданные параметры
        this.hmacAlgorithm = RefObject.addRef(hmacAlgorithm); 
    } 
    // освободить ресурсы 
    @Override protected void onClose() throws IOException
    { 
        // освободить ресурсы 
        RefObject.release(hmacAlgorithm); super.onClose();
    }
	// сгенерировать блок данных
	@Override public ISecretKey deriveKey(ISecretKey key, 
        byte[] random, SecretKeyFactory keyFactory, int deriveSize) 
        throws IOException, InvalidKeyException
	{
        // проверить наличие размера
        if (deriveSize < 0) throw new IllegalStateException(); 
        
        // проверить корректность ключа
        byte[] z = key.value(); if (z == null) throw new InvalidKeyException(); 
        
        // проверить наличие дополнительных данных
        if (random == null) random = new byte[0]; 
        
        // выделить требуемую память и определить размер хэш-значения
        byte[] KEK = new byte[deriveSize]; int hmacLen = hmacAlgorithm.macSize();

        // закодировать данные для хэширования
        byte[] buffer = Array.concat(new byte[4], z, random, new byte[4]);
        
        // закодировать размер в битах
        Convert.fromInt32(deriveSize * 8, ENDIAN, buffer, buffer.length - 4);

        // для каждого блока ключа шифрования ключа
        for (int i = 0; i < (deriveSize + hmacLen - 1) / hmacLen; i++)
        {
            // закодировать номер блока
            Convert.fromInt32(i + 1, ENDIAN, buffer, 0);

            // захэшировать данные
            byte[] hash = hmacAlgorithm.macData(key, buffer, 0, buffer.length); 

            // скопировать часть ключа
            if (deriveSize >= (i + 1) * hmacLen) System.arraycopy(hash, 0, KEK, i * hmacLen, hmacLen); 

             // скопировать часть ключа
            else System.arraycopy(hash, 0, KEK, i * hmacLen, deriveSize - i * hmacLen); 
        }
        return keyFactory.create(KEK); 
    }
}

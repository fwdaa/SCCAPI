package aladdin.capi.ansi.derive;
import aladdin.*; 
import aladdin.math.*;
import aladdin.capi.*; 
import aladdin.util.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Наследование ключа SP800-56A
///////////////////////////////////////////////////////////////////////////
public class SP800_56A extends KeyDerive
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
	// алгоритм хэширования
    private final Hash hashAlgorithm;
    
	// конструктор
	public SP800_56A(Hash hashAlgorithm) 
    { 
        // сохранить переданные параметры
        this.hashAlgorithm = RefObject.addRef(hashAlgorithm); 
    } 
    // освободить ресурсы 
    @Override protected void onClose() throws IOException 
    { 
        // освободить ресурсы 
        RefObject.release(hashAlgorithm); super.onClose();            
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
        byte[] KEK = new byte[deriveSize]; int hashLen = hashAlgorithm.hashSize();

        // закодировать данные для хэширования
        byte[] buffer = Array.concat(new byte[4], z, random);
        
        // для каждого блока ключа шифрования ключа
        for (int i = 0; i < (deriveSize + hashLen - 1) / hashLen; i++)
        {
            // закодировать номер блока
            Convert.fromInt32(i + 1, ENDIAN, buffer, 0);

            // захэшировать данные
            byte[] hash = hashAlgorithm.hashData(buffer, 0, buffer.length); 

            // скопировать часть ключа
            if (deriveSize >= (i + 1) * hashLen) System.arraycopy(hash, 0, KEK, i * hashLen, hashLen); 

            // скопировать часть ключа
            else System.arraycopy(hash, 0, KEK, i * hashLen, deriveSize - i * hashLen); 
        }
        return keyFactory.create(KEK); 
	}
}

package aladdin.capi.ansi.derive;
import aladdin.*; 
import aladdin.math.*;
import aladdin.capi.*; 
import aladdin.util.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Наследование ключа X.963
///////////////////////////////////////////////////////////////////////////
public class X963KDF extends KeyDerive
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
	// алгоритм хэширования
    private final Hash hashAlgorithm;
    
	// конструктор
	public X963KDF(Hash hashAlgorithm) 
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
        
        // закодировать данные для хэширования
        byte[] buffer = Array.concat(z, new byte[4], random);
        
        // выделить требуемую память и определить размер хэш-значения
        byte[] KEK = new byte[deriveSize]; int hashLen = hashAlgorithm.hashSize();

        // для каждого блока ключа шифрования ключа
        for (int i = 0; i < (deriveSize + hashLen - 1) / hashLen; i++)
        {
            // закодировать номер блока
            Convert.fromInt32(i + 1, ENDIAN, buffer, z.length);

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

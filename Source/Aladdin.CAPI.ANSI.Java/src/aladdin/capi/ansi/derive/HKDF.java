package aladdin.capi.ansi.derive;
import aladdin.*; 
import aladdin.math.*;
import aladdin.asn1.*; 
import aladdin.asn1.ansi.x962.*; 
import aladdin.capi.*; 
import aladdin.util.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Наследование ключа HKDF (RFC 5869)
///////////////////////////////////////////////////////////////////////////
public class HKDF extends KeyDerive
{
	// алгоритм HMAC
    private final Mac hmacAlgorithm; private final byte[] salt; 
    
	// конструктор
	public HKDF(Mac hmacAlgorithm) { this(hmacAlgorithm, null); }
	// конструктор
	public HKDF(Mac hmacAlgorithm, byte[] salt) 
    { 
        // сохранить переданные параметры
        this.hmacAlgorithm = RefObject.addRef(hmacAlgorithm); this.salt = salt; 
    } 
    // освободить ресурсы 
    @Override protected void onClose() throws IOException
    { 
        // освободить ресурсы 
        RefObject.release(hmacAlgorithm); super.onClose();
    }
    // получить начальное значение
    protected byte[] getSalt(byte[] random) throws IOException
    {
        // вернуть начальное значение
        if (salt != null) return salt; if (random == null) throw new IllegalStateException();

        // раскодировать случайные данные
        SharedInfo sharedInfo = new SharedInfo(Encodable.decode(random)); 

        // указать случайные данные
        return (sharedInfo.entityUInfo() != null) ? sharedInfo.entityUInfo().value() : null; 
    }
	    // согласовать ключ
	@Override public ISecretKey deriveKey(ISecretKey key, 
        byte[] random, SecretKeyFactory keyFactory, int deriveSize) 
        throws IOException, InvalidKeyException
    {
        // проверить наличие размера
        if (deriveSize < 0) throw new IllegalStateException(); 

        // проверить корректность ключа
        byte[] z = key.value(); if (z == null) throw new InvalidKeyException(); 

        // указать начальное значение
        byte[] salt = getSalt(random); if (salt == null) salt = new byte[0];  

        // указать случайные данные
        byte[] info = random; if (info == null) info = new byte[0];

        // выделить требуемую память и определить размер хэш-значения
        byte[] KEK = new byte[deriveSize]; int hmacLen = hmacAlgorithm.macSize();

        // указать фабрику создания ключей
        SecretKeyFactory genericFactory = SecretKeyFactory.GENERIC; 

        // создать ключ HMAC
        ISecretKey hmacKey = genericFactory.create(salt); 

        // выполнить хэширование
        ISecretKey PRK = genericFactory.create(hmacAlgorithm.macData(hmacKey, z, 0, z.length)); 

        // закодировать данные для хэширования
        byte[] buffer = Array.concat(new byte[hmacLen], info, new byte[1]);
        
        // для каждого блока ключа шифрования ключа
        for (int i = 0, offset = hmacLen; i < (deriveSize + hmacLen - 1) / hmacLen; i++, offset = 0)
        {
            // закодировать номер блока
            buffer[buffer.length - 1] = (byte)(i + 1); 

            // захэшировать данные
            byte[] mac = hmacAlgorithm.macData(PRK, buffer, offset, buffer.length - offset); 

            // скопировать часть ключа
            if (deriveSize >= (i + 1) * hmacLen) System.arraycopy(mac, 0, KEK, i * hmacLen, hmacLen); 

            // скопировать часть ключа
            else System.arraycopy(mac, 0, KEK, i * hmacLen, deriveSize - i * hmacLen); 
        }
        return keyFactory.create(KEK); 
    }
}

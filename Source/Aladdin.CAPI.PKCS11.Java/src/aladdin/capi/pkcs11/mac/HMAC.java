package aladdin.capi.pkcs11.mac;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки HMAC
///////////////////////////////////////////////////////////////////////////////
public abstract class HMAC extends aladdin.capi.pkcs11.Mac
{
    // тип ключа и размер имитовставки в байтах
    private final long keyType; private final int macSize;
    // алгоритм хэширования и буфер для хэш-значения
    private aladdin.capi.Mac hMAC; private byte[] hash; 
    
    // конструктор
    public HMAC(Applet applet, int macSize) 
    { 
        // сохранить переданные параметры
        this(applet, API.CKK_GENERIC_SECRET, macSize); 
    }
    // конструктор
    public HMAC(Applet applet, long keyType, int macSize)
    { 
        // сохранить переданные параметры
        super(applet); this.keyType = keyType; this.macSize = macSize; hMAC = null;
    }
	// атрибуты ключа
	@Override protected Attribute[] getKeyAttributes(int keySize)
    { 
        // вернуть атрибуты ключа
		if (hash == null) return super.getKeyAttributes(keySize); 

        // указать тип ключа
        return new Attribute[] { new Attribute(API.CKA_KEY_TYPE, keyType) }; 
    }
    // размер имитовставки в байтах
    @Override public int macSize() { return macSize; }
    // размер имитовставки в байтах
    @Override public int blockSize() { return getHashAlgorithm().blockSize(); }

    // инициализировать алгоритм
	@Override public void init(ISecretKey key) throws IOException, InvalidKeyException
    {
        // освободить выделенные ресурсы
        if (hMAC != null) hMAC.close(); hMAC = null; hash = null; 

        // получить алгоритм хэширования
        aladdin.capi.Hash hashAlgorithm = getHashAlgorithm(); 
        
        // выделить буфер для хэш-значения
        if (isSpecialKey(key)) { hash = new byte[hashAlgorithm.hashSize()]; 
            
            // создать алгоритм вычисления имитовставки
            hMAC = new aladdin.capi.mac.HMAC(hashAlgorithm); hMAC.init(key); return;         
        }
        // инициализировать алгоритм
        try { super.init(key); return; }
            
        // при возникновении ошибки
        catch (aladdin.pkcs11.Exception e) { 
            
            // проверить код ошибки
            if (e.getErrorCode() != API.CKR_ATTRIBUTE_VALUE_INVALID) throw e; 
        }
        // выделить буфер для хэш-значения
        hash = new byte[hashAlgorithm.hashSize()]; 
            
        // инициализировать алгоритм
        try { super.init(key); return; }
            
        // при возникновении ошибки
        catch (aladdin.pkcs11.Exception e) 
        { 
            // проверить код ошибки
            if (e.getErrorCode() != API.CKR_ATTRIBUTE_VALUE_INVALID) throw e; 
        }
	    // создать алгоритм вычисления имитовставки
	    hMAC = new aladdin.capi.mac.HMAC(hashAlgorithm); hMAC.init(key);         
    }
	// захэшировать данные
	@Override public void update(byte[] data, int dataOff, int dataLen) throws IOException
	{
		// вызвать базовую функцию
		if (hMAC == null) super.update(data, dataOff, dataLen); 

		// захэшировать данные
		else hMAC.update(data, dataOff, dataLen); 
	}
	// получить имитовставку
	@Override public int finish(byte[] buffer, int bufferOff) throws IOException
	{
		// вызвать базовую функцию
		if (hMAC == null) super.finish(hash, 0);
        else { 
		    // получить имитовставку
		    hMAC.finish(hash, 0); hMAC.close(); hMAC = null;
        }
        // скопировать хэш-значение
        System.arraycopy(hash, 0, buffer, bufferOff, macSize); return macSize; 
	}
    // признак специального ключа
    protected boolean isSpecialKey(ISecretKey key) { return (key.length() == 0); }
    
    // получить алгоритм хэширования
    protected abstract aladdin.capi.Hash getHashAlgorithm(); 
}

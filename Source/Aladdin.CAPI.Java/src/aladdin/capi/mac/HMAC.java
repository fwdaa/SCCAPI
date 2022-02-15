package aladdin.capi.mac;
import aladdin.*; 
import aladdin.capi.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки HMAC
///////////////////////////////////////////////////////////////////////////////
public class HMAC extends Mac
{
	// алгоритм хэширования, размер блока и ключ
	private final Hash algorithm; private final int blockSize; private final byte[] key;
    
	// конструктор
	public HMAC(Hash algorithm) 
    { 
		// сохранить переданные параметры
		this.algorithm = RefObject.addRef(algorithm); 
 
		// выделить память для ключа
		blockSize = algorithm.blockSize(); this.key = new byte[blockSize];
	}
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    { 
        // освободить выделенные ресурсы
        RefObject.release(algorithm); super.onClose();
    }
	// размер MAC-значения в байтах
	@Override public int macSize() { return algorithm.hashSize(); }
    
    // размер блока в байтах 
	@Override public int blockSize() { return algorithm.blockSize(); }

	// инициализировать алгоритм
	@Override public void init(ISecretKey key) throws IOException, InvalidKeyException
	{
		// проверить тип ключа
		if (key.value() == null) throw new InvalidKeyException();
        
        // получить значение ключа
        byte[] value = key.value(); if (value.length > blockSize)
        {
			// прохэшировать ключ
			value = algorithm.hashData(value, 0, value.length); 
        }
        // скопировать ключ
		if (value.length > blockSize) System.arraycopy(value, 0, this.key, 0, blockSize);
        else {
            // скопировать ключ
            System.arraycopy(value, 0, this.key, 0, value.length);
            
            // обнулить неиспользуемые данных
            for (int i = value.length; i < this.key.length; i++) this.key[i] = 0; 
        } 
		// скопировать ключ для хэширования
		byte[] k_ipad = this.key.clone(); 

		// дополнить ключ
		for (int i = 0; i < blockSize; i++) k_ipad[i] ^= 0x36;

		// прохэшировать дополненный ключ
		algorithm.init(); algorithm.update(k_ipad, 0, blockSize);

		// обнулить ключ для хэширования
		for (int i = 0; i < blockSize; i++) k_ipad[i] = 0;
	}
	// захэшировать данные
	@Override public void update(byte[] data, int dataOff, int dataLen) throws IOException
	{
		// прохэшировать данные
		algorithm.update(data, dataOff, dataLen);
	}
	// получить MAC-значение
	@Override public int finish(byte[] buf, int bufOff) throws IOException
	{
		// выделить буфер для хэш-значения
		byte[] hash = new byte[algorithm.hashSize()]; 

		// вычислить хэш-значение
		int cbHash = algorithm.finish(hash, 0); 

		// выделить память для завершающего хэширования
		byte[] k_opad = new byte[blockSize + cbHash];
 
		// скопировать ключ и хэш-значение
		System.arraycopy(key,  0, k_opad,      0, blockSize); 
		System.arraycopy(hash, 0, k_opad, blockSize, cbHash); 
			
		// дополнить ключ
		for (int i = 0; i < blockSize; i++) k_opad[i] ^= 0x5C;

		// выполнить завершающее хэширование
		hash = algorithm.hashData(k_opad, 0, k_opad.length);

		// обнулить ключ для хэширования
		for (int i = 0; i < blockSize; i++) k_opad[i] = 0; 
			
		// скопировать хэш-значение
		System.arraycopy(hash, 0, buf, bufOff, hash.length); return hash.length; 
	}
}

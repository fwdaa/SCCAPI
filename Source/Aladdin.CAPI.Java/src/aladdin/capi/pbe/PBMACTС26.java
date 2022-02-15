package aladdin.capi.pbe;
import aladdin.capi.*;
import aladdin.capi.mac.*;
import java.security.*;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки по паролю PBMAC PKCS12 TK26
///////////////////////////////////////////////////////////////////////////
public class PBMACTС26 extends Mac
{
	// алгоритм вычисления имитовставки и наследования ключа
	private final Mac macAlgorithm; private final KeyDerive derivationAlgorithm; 
    
	// конструктор
	public PBMACTС26(Hash hashAlgorithm, byte[] salt, int iterations)
	{
		// создать алгоритм вычисления имитовставки
		macAlgorithm = new HMAC(hashAlgorithm);  
 
        // создать алгоритм наследования ключа
        derivationAlgorithm = new PBKDF2(macAlgorithm, salt, iterations, -1); 
	}
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException 
    { 
        // освободить выделенные ресурсы
        derivationAlgorithm.close(); 
        
        // освободить выделенные ресурсы
        macAlgorithm.close(); super.onClose();        
    } 
	// размер MAC-значения в байтах
	@Override public int macSize() { return macAlgorithm.macSize(); } 

    // размер блока в байтах 
	@Override public int blockSize() { return macAlgorithm.blockSize(); }
    
	// инициализировать алгоритм
	@Override public void init(ISecretKey password) throws IOException, InvalidKeyException
	{
		// определить размер ключа
		SecretKeyFactory keyFactory = SecretKeyFactory.GENERIC; 

        // сгенерировать случайные данные
        try (ISecretKey key = derivationAlgorithm.deriveKey(password, null, keyFactory, 96))
        {  
            // извлечь последние байты
            byte[] value = Arrays.copyOfRange(key.value(), 64, 96); 
            
            // инициализировать алгоритм вычисления имитовставки
            try (ISecretKey k = keyFactory().create(value)) { macAlgorithm.init(k); }
        }
	}
	// захэшировать данные
	@Override public void update(byte[] data, int dataOff, int dataLen) throws IOException
	{
		// захэшировать данные
		macAlgorithm.update(data, dataOff, dataLen); 
	}
	// получить MAC-значение
	@Override public int finish(byte[] buf, int bufOff) throws IOException
	{
		// получить MAC-значение
		return macAlgorithm.finish(buf, bufOff); 
	}
}

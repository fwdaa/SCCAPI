package aladdin.capi.pbe;
import aladdin.capi.*;
import aladdin.capi.mac.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки по паролю PBMAC PKCS12
///////////////////////////////////////////////////////////////////////////
public class PBMACP12 extends Mac
{
	// алгоритм вычисления имитовставки и наследования ключа
	private final Mac macAlgorithm; private final KeyDerive derivationAlgorithm; 
    
	// конструктор
	public PBMACP12(Hash hashAlgorithm, byte[] salt, int iterations)
    {
		// создать алгоритм вычисления имитовставки
		macAlgorithm = new HMAC(hashAlgorithm); 
 
        // создать алгоритм наследования ключа
        derivationAlgorithm = new PBKDFP12(hashAlgorithm, salt, iterations, (byte)3); 
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
        // определить тип и размер ключа
        SecretKeyFactory keyFactory = macAlgorithm.keyFactory(); 
        
        // наследовать ключ по паролю
        try (ISecretKey key = derivationAlgorithm.deriveKey(
            password, null, keyFactory, macAlgorithm.macSize()))
        {
            // инициализировать алгоритм
            macAlgorithm.init(key); 
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

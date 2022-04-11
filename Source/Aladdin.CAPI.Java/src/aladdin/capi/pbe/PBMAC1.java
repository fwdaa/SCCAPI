package aladdin.capi.pbe;
import aladdin.*; 
import aladdin.capi.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки по паролю PBMAC1
///////////////////////////////////////////////////////////////////////////
public class PBMAC1 extends Mac
{
	private final KeyDerive derivationAlgorithm;   // алгоритм наследования
	private final Mac       macAlgorithm;          // алгоритм вычисления имитовставки
    
	// конструктор 
	public PBMAC1(KeyDerive derivationAlgorithm, Mac macAlgorithm) 
	{
        // сохранить переданные параметры
		this.derivationAlgorithm = RefObject.addRef(derivationAlgorithm);
		this.macAlgorithm		 = RefObject.addRef(macAlgorithm);
	}
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException 
    { 
        // освободить выделенные ресурсы
        RefObject.release(derivationAlgorithm); 
        
        // освободить выделенные ресурсы
        RefObject.release(macAlgorithm); super.onClose();        
    } 
	// размер MAC-значения в байтах
	@Override public int macSize() { return macAlgorithm.macSize(); } 

    // размер блока в байтах 
	@Override public int blockSize() { return macAlgorithm.blockSize(); }
    
    // инициализировать алгоритм
	@Override public void init(ISecretKey password) throws IOException, InvalidKeyException 
	{
        // определить тип ключа
        SecretKeyFactory keyFactory = macAlgorithm.keyFactory(); int keySize = -1; 
        
        // определить допустимые размеры ключей
        int[] keySizes = macAlgorithm.keyFactory().keySizes(); 
        
        // указать рекомендуемый размер ключа
        if (keySizes != null && keySizes.length == 1) keySize = keySizes[0]; 
        
		// наследовать ключ по паролю
		try (ISecretKey key = derivationAlgorithm.deriveKey(
            password, null, keyFactory, keySize)) 
        {
            // проверить допустимость размера ключа
            if (!KeySizes.contains(keySizes, key.length())) 
            {
                // выбросить исключение
                throw new IllegalStateException();
            }
            // инииализировать алгоритм
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

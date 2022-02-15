package aladdin.capi.pbe;
import aladdin.*; 
import aladdin.capi.*;
import aladdin.util.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки по паролю PKIX
///////////////////////////////////////////////////////////////////////////
public class PBMAC extends Mac
{
	private final Hash   hashAlgorithm;	// алгоритм хэширования
	private final Mac    macAlgorithm;	// алгоритм вычисления имитовставки
	private final int	 keySize;		// размер ключа алгоритма
	private final byte[] salt;			// salt-значение
	private final int	 iterations;	// число итераций
    
	// конструктор 
	public PBMAC(Hash hashAlgorithm, Mac macAlgorithm, byte[] salt, int iterations) 
	{
        // получить допустимые размеры ключей
        int[] keySizes = macAlgorithm.keySizes(); 
        
        // проверить наличие ключей фиксированного размера
        if (keySizes == null || keySizes.length != 1) 
        {
            // при ошибке выбросить исключение
            throw new IllegalStateException();
        } 
        // сохранить переданные параметры
		this.hashAlgorithm	= RefObject.addRef(hashAlgorithm);
		this.macAlgorithm	= RefObject.addRef(macAlgorithm);
        
        // сохранить переданные параметры
        this.keySize = keySizes[0]; this.salt = salt; this.iterations = iterations;
	}
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException 
    {
        // освободить используемые ресурсы
        RefObject.release(hashAlgorithm); 
        
        // освободить используемые ресурсы
        RefObject.release(macAlgorithm); super.onClose();        
    }
	// размер MAC-значения в байтах
	@Override public int macSize() { return macAlgorithm.macSize(); } 

    // размер блока в байтах 
	@Override public int blockSize() { return macAlgorithm.blockSize(); }
    
	// инициализировать алгоритм
	@Override public void init(ISecretKey password) throws IOException, InvalidKeyException 
	{
		// проверить тип ключа
		if (password.value() == null) throw new InvalidKeyException();

		// объединить пароль с salt-значением
		byte[] K = Array.concat(password.value(), salt); 

		// захэшировать пароль и salt-значение
		K = hashAlgorithm.hashData(K, 0, K.length); 
			
		// выполнить требуемое число итераций
		for (int i = 0; i < iterations; i++)
		{
			// захэшировать ключ
			K = hashAlgorithm.hashData(K, 0, K.length); 
		}
		// выделить память для ключа
		byte[] key = new byte[keySize]; 

		// проверьть необходимость расширения ключа
		if (K.length >= key.length) System.arraycopy(K, 0, key, 0, key.length); 
		else {
			// скопировать ключ
			System.arraycopy(K, 0, key, 0, K.length); int ofs = K.length; 

			// для всех полных блоков
			for (int i = 1; ofs < key.length; ofs += K.length, i++)
			{
				// закодировать номер
				try { byte[] number = Integer.toString(i).getBytes("US-ASCII"); 
                
                    // объединить номер с ключом
                    byte[] data = Array.concat(number, K); 

                    // захэшировать ключ
                    K = hashAlgorithm.hashData(data, 0, data.length); 
                }
                // обработать неожидаемое исключение
                catch (UnsupportedEncodingException e) { throw new RuntimeException(e); }

				// скопировать ключ
				System.arraycopy(K, 0, key, ofs, (K.length < key.length - ofs) ? K.length : key.length - ofs);
			}
		}
		// инициализировать алгоритм
		try (ISecretKey k = keyFactory().create(key)) { macAlgorithm.init(k); }
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

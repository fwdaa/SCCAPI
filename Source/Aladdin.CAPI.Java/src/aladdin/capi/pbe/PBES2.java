package aladdin.capi.pbe;
import aladdin.*; 
import aladdin.capi.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования по паролю PBES2
///////////////////////////////////////////////////////////////////////////
public class PBES2 extends Cipher
{
	private final KeyDerive derivationAlgorithm;    // алгоритм наследования
	private final Cipher    cipherAlgorithm;        // алгоритм шифрования
    
	// конструктор 
	public PBES2(KeyDerive derivationAlgorithm, Cipher cipherAlgorithm) 
	{
        // сохранить переданные параметры
		this.derivationAlgorithm = RefObject.addRef(derivationAlgorithm);
		this.cipherAlgorithm	 = RefObject.addRef(cipherAlgorithm);	
	}
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException 
    { 
        // освободить выделенные ресурсы
        RefObject.release(derivationAlgorithm); 
        
        // освободить выделенные ресурсы
        RefObject.release(cipherAlgorithm); super.onClose();        
    } 
    // размер блока алгоритма
    @Override public int blockSize() { return cipherAlgorithm.blockSize(); }
    
	// алгоритм зашифрования данных
	@Override protected Transform createEncryption(ISecretKey password) 
        throws IOException, InvalidKeyException
	{
        // определить тип ключа
        SecretKeyFactory keyFactory = cipherAlgorithm.keyFactory(); int keySize = -1; 
        
        // определить допустимые размеры ключей
        int[] keySizes = cipherAlgorithm.keySizes(); 
        
        // указать рекомендуемый размер ключа
        if (keySizes != null && keySizes.length == 1) keySize = keySizes[0]; 
        
		// наследовать ключ по паролю
		try (ISecretKey key = derivationAlgorithm.deriveKey(password, null, keyFactory, keySize)) 
        {
            // проверить допустимость размера ключа
            if (!KeySizes.contains(keySizes, key.length())) 
            {
                // выбросить исключение
                throw new IllegalStateException();
            }
            // вернуть преобразование зашифрования
            return cipherAlgorithm.createEncryption(key, PaddingMode.PKCS5); 
        }
	}
	// алгоритм расшифрования данных
	@Override protected Transform createDecryption(ISecretKey password) 
        throws IOException, InvalidKeyException
	{
        // определить тип ключа
        SecretKeyFactory keyFactory = cipherAlgorithm.keyFactory(); int keySize = -1; 
        
        // определить допустимые размеры ключей
        int[] keySizes = cipherAlgorithm.keySizes(); 
        
        // указать рекомендуемый размер ключа
        if (keySizes != null && keySizes.length == 1) keySize = keySizes[0]; 
        
        // наследовать ключ по паролю
		try (ISecretKey key = derivationAlgorithm.deriveKey(password, null, keyFactory, keySize))
        {
            // проверить допустимость размера ключа
            if (!KeySizes.contains(keySizes, key.length())) 
            {
                // выбросить исключение
                throw new IllegalStateException();
            }
            // вернуть преобразование расшифрования
            return cipherAlgorithm.createDecryption(key, PaddingMode.PKCS5); 
        }
	}
}

package aladdin.capi.pbe;
import aladdin.*; 
import aladdin.capi.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования по паролю PKCS12 
///////////////////////////////////////////////////////////////////////////
public class PBESP12 extends Cipher
{
	// используемые алгоритмы наследования
    private final KeyDerive keyDerive; private final KeyDerive ivDerive; 
    // алгоритм шифрования и тип ключа
    private final IAlgorithm cipher; private final SecretKeyFactory keyFactory; 
    // размер ключа
    private final int keyLength; 

	// конструктор 
	public PBESP12(IBlockCipher cipher, int keyLength, Hash hashAlgorithm, byte[] salt, int iterations)
	{
        // сохранить переданные параметры
        this.keyFactory = cipher.keyFactory(); this.keyLength = keyLength; 
        
        // сохранить переданные параметры
        this.cipher = RefObject.addRef(cipher); 
        
		// создать алгоритм наследования ключа
		keyDerive = new PBKDFP12(hashAlgorithm, salt, iterations, (byte)1); 

		// создать алгоритм наследования вектора инициализации
		ivDerive = new PBKDFP12(hashAlgorithm, salt, iterations, (byte)2); 
	}
	public PBESP12(Cipher cipher, int keyLength, Hash hashAlgorithm, byte[] salt, int iterations)
	{
        // сохранить переданные параметры
        this.keyFactory = cipher.keyFactory(); this.keyLength = keyLength; 
        
        // сохранить переданные параметры
        this.cipher = RefObject.addRef(cipher); 
        
		// создать алгоритм наследования ключа
		keyDerive = new PBKDFP12(hashAlgorithm, salt, iterations, (byte)1); 

		// создать алгоритм наследования вектора инициализации
		ivDerive = new PBKDFP12(hashAlgorithm, salt, iterations, (byte)2); 
	}
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException 
    { 
        // освободить выделенные ресурсы
        RefObject.release(cipher);
        
        // освободить выделенные ресурсы
        ivDerive.close(); keyDerive.close(); super.onClose();        
    } 
    // размер блока алгоритма
	@Override public int blockSize() 
    { 
        // вернуть размер блока алгоритма
        if (cipher instanceof Cipher) return ((Cipher)cipher).blockSize(); 
            
        // вернуть размер блока алгоритма
        else return ((IBlockCipher)cipher).blockSize(); 
    } 
	// создать алгоритм шифрования
	protected Cipher createCipher(byte[] iv) throws IOException
    {
        // проверить тип алгоритма
        if (cipher instanceof Cipher) return RefObject.addRef((Cipher)cipher); 
        else {
            // указать режим блочного алгоритма
            CipherMode parameters = new CipherMode.CBC(iv);
        
            // получить алгоритм шифрования
            Cipher mode = ((IBlockCipher)cipher).createBlockMode(parameters); 
        
            // проверить наличие алгоритма
            if (mode == null) throw new UnsupportedOperationException(); return mode;  
        }
    }
	// алгоритм зашифрования данных
	@Override protected Transform createEncryption(ISecretKey password) 
        throws IOException, InvalidKeyException
	{
		// наследовать ключ по паролю
		try (ISecretKey key = keyDerive.deriveKey(password, null, keyFactory, keyLength))
        {
            // наследовать вектор инициализации 
            try (ISecretKey iv = ivDerive.deriveKey(password, null, SecretKeyFactory.GENERIC, blockSize()))
            {
                // проверить тип ключа
                if (iv.value() == null) throw new InvalidKeyException();
        
                // создать алгоритм шифрования
                try (Cipher cipher = createCipher(iv.value()))
                {
                    // вернуть преобразование зашифрования
                    return cipher.createEncryption(key, PaddingMode.PKCS5);
                }
            }
        }
	}
	// алгоритм расшифрования данных
	@Override protected Transform createDecryption(ISecretKey password) 
        throws IOException, InvalidKeyException
	{
		// наследовать ключ по паролю
		try (ISecretKey key = keyDerive.deriveKey(password, null, keyFactory, keyLength))
        {
            // наследовать вектор инициализации 
            try (ISecretKey iv = ivDerive.deriveKey(password, null, SecretKeyFactory.GENERIC, blockSize()))
            {
                // проверить тип ключа
                if (iv.value() == null) throw new InvalidKeyException();
 
                // создать алгоритм шифрования
                try (Cipher cipher = createCipher(iv.value()))
                {
                    // вернуть преобразование расшифрования
                    return cipher.createDecryption(key, PaddingMode.PKCS5);
                }
            }
        }
	}
}

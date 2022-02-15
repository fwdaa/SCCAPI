package aladdin.capi.pbe;
import aladdin.capi.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования по паролю PBES1
///////////////////////////////////////////////////////////////////////////
public abstract class PBES1 extends Cipher
{
	// алгоритм наследования ключа по паролю
	private final KeyDerive algorithm; private final SecretKeyFactory keyFactory; 

	// конструктор 
	protected PBES1(Hash hashAlgorithm, byte[] salt, int iterations, SecretKeyFactory keyFactory)
	{
		// создать алгоритм наследования ключа
        algorithm = new PBKDF1(hashAlgorithm, salt, iterations); this.keyFactory = keyFactory; 
	}
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException 
    { 
        // освободить выделенные ресурсы
        algorithm.close(); super.onClose();         
    } 
    // размер блока алгоритма
	@Override public int blockSize() { return ivLength(); } 

	// создать алгоритм шифрования
	protected abstract Cipher createCipher(byte[] iv) throws IOException; 

	// размер ключа и вектора инициализации
	protected abstract int keyLength();  
	protected abstract int ivLength ();  

	// алгоритм зашифрования данных
	@Override protected Transform createEncryption(ISecretKey password) 
        throws IOException, InvalidKeyException
	{
        // выделить память для синхропосылки
        byte[] iv = new byte[ivLength() > 1 ? ivLength() : 0]; 
        
		// наследовать ключ и вектор инициализации по паролю
        try (ISecretKey key = algorithm.deriveKey(password, iv, keyFactory, keyLength())) 
        {
            // создать алгоритм шифрования
            try (Cipher cipher = createCipher(iv))
            {
                // вернуть преобразование зашифрования
                return cipher.createEncryption(key, PaddingMode.PKCS5); 
            }
        }
	}
	// алгоритм расшифрования данных
	@Override protected Transform createDecryption(ISecretKey password) 
        throws IOException, InvalidKeyException
	{
        // выделить память для синхропосылки
        byte[] iv = new byte[ivLength() > 1 ? ivLength() : 0]; 
        
		// наследовать ключ и вектор инициализации по паролю
        try (ISecretKey key = algorithm.deriveKey(password, iv, keyFactory, keyLength())) 
        {
            // создать алгоритм шифрования
            try (Cipher cipher = createCipher(iv))
            {
                // вернуть преобразование расшифрования
                return cipher.createDecryption(key, PaddingMode.PKCS5); 
            }
        }
	}
}

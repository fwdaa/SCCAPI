package aladdin.capi.pbe;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.util.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа PBKDF1
///////////////////////////////////////////////////////////////////////////
public class PBKDF1 extends KeyDerive
{
	private final Hash   hashAlgorithm; // алгоритм хэширования
	private final byte[] salt; 			// salt-значение
	private final int	 iterations;	// число итераций

	// конструктор
	public PBKDF1(Hash hashAlgorithm, byte[] salt, int iterations) 
	{ 
        // сохранить переданные параметры
		this.hashAlgorithm	= RefObject.addRef(hashAlgorithm);
        
        // сохранить переданные параметры
		this.salt = salt; this.iterations = iterations;
	}
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException 
    { 
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); super.onClose();        
    } 
	// наследовать ключ
	@Override public ISecretKey deriveKey(ISecretKey password, 
        byte[] iv, SecretKeyFactory keyFactory, int deriveSize) 
            throws IOException, InvalidKeyException
	{
        // проверить наличие буфера для синхропосылки
        if (iv == null) iv = new byte[0]; 
        
		// проверить тип ключа
		if (password.value() == null) throw new InvalidKeyException();

		// проверить корректность параметров
		if (deriveSize + iv.length > hashAlgorithm.hashSize()) 
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException();
        }
		// объединить пароль и salt-значение 
		byte[] pass_salt = Array.concat(password.value(), salt); 

		// вычислить хэш-значение от объединения
		byte[] hash = hashAlgorithm.hashData(pass_salt, 0, pass_salt.length); 

        // для всех итераций
		for (int i = 1; i < iterations; i++)
		{
			// вычислить хэш-значение от хэш-значения
			hash = hashAlgorithm.hashData(hash, 0, hash.length); 
		}
		// извлечь ключ
        byte[] key = new byte[deriveSize]; System.arraycopy(hash, 0, key, 0, key.length);

        // извлечь вектор инициализации и вернуть ключ
        System.arraycopy(hash, key.length, iv, 0, iv.length); return keyFactory.create(key);
 	}
}

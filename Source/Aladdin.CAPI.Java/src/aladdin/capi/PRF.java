package aladdin.capi;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм псевдослучайной генерации
///////////////////////////////////////////////////////////////////////////
public abstract class PRF extends KeyDerive
{
    // выполнить генерацию / наследовать ключ
    @Override
	public ISecretKey deriveKey(ISecretKey key, byte[] random, 
        SecretKeyFactory keyFactory, int deriveSize) 
        throws IOException, InvalidKeyException
    {
        // проверить наличие значения ключа
        if (key.value() == null) throw new InvalidKeyException(); 
        
        // выделить буфер требуемого размера
        byte[] buffer = new byte[deriveSize]; 

	    // выполнить генерацию данных
	    generate(key.value(), random, buffer, 0, deriveSize); 

        // создать ключ
        return keyFactory.create(buffer); 
    }
	// выполнить генерацию данных
	public abstract void generate(byte[] key, 
        byte[] random, byte[] buffer, int offset, int deriveSize) 
        throws IOException;
}

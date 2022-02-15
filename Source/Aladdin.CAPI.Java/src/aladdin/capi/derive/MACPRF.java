package aladdin.capi.derive;
import aladdin.*; 
import aladdin.capi.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Реализация псевдослучайной функции на основе алгоритма HMAC
///////////////////////////////////////////////////////////////////////////
public class MACPRF extends PRF
{
	// алгоритм вычисления HMAC
	private final Mac algorithm;

	// конструктор
	public MACPRF(Mac algorithm) 
    { 
        // сохранить переданные параметры
        this.algorithm = RefObject.addRef(algorithm); 
    } 
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    { 
        // освободить выделенные ресурсы
        RefObject.release(algorithm); super.onClose();
    } 
    // тип ключа
    @Override public SecretKeyFactory keyFactory() { return algorithm.keyFactory(); } 
    // размер ключей
    @Override public int[] keySizes() { return algorithm.keySizes(); } 
    
    // наследовать ключ
	@Override public void generate(byte[] keyValue, byte[] random, 
        byte[] buffer, int offset, int deriveSize) throws IOException
	{ 
        // указать размер ключа
        if (deriveSize < 0) deriveSize = algorithm.macSize(); 
        
        // проверить коррректность параметров
        if (deriveSize != algorithm.macSize()) throw new UnsupportedOperationException(); 
        
        // указать используемый ключ
        try (ISecretKey key = algorithm.keyFactory().create(keyValue))
        {
            // вычислить MAC-значение
            byte[] mac = algorithm.macData(key, random, 0, random.length); 
        
            // скопировать MAC-значение
            System.arraycopy(mac, 0, buffer, offset, deriveSize); 
        }
        // обработать неожидаемое исключение
        catch (InvalidKeyException e) { throw new IOException(e); } 
	} 
}

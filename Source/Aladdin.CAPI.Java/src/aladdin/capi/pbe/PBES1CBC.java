package aladdin.capi.pbe;
import aladdin.*; 
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования по паролю PBES1 с использованием режима CBC
///////////////////////////////////////////////////////////////////////////
public class PBES1CBC extends PBES1
{
    // блочный алгоритм шифрования и размер ключа
    private final IBlockCipher blockCipher; private final int keyLength; 
    
	// конструктор 
	public PBES1CBC(IBlockCipher blockCipher, int keyLength, 
        Hash hashAlgorithm, byte[] salt, int iterations)
    {
        // сохранить переданные параметры			
        super(hashAlgorithm, salt, iterations, blockCipher.keyFactory()); 
        
        // сохранить переданные параметры	
        this.blockCipher = RefObject.addRef(blockCipher); this.keyLength = keyLength; 
    } 
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(blockCipher); super.onClose();
    }
    // создать алгоритм шифрования
	@Override protected Cipher createCipher(byte[] iv) throws IOException
	{
        // указать параметры режима
        CipherMode mode = new CipherMode.CBC(iv); 
        
        // получить алгоритм шифрования
        Cipher cipher = blockCipher.createBlockMode(mode); 
        
        // проверить наличие алгоритма
        if (cipher == null) throw new UnsupportedOperationException(); return cipher;  
	}
	// размер ключа и вектора инициализации
	@Override protected final int keyLength() { return keyLength;               } 
	@Override protected final int ivLength () { return blockCipher.blockSize(); } 
}

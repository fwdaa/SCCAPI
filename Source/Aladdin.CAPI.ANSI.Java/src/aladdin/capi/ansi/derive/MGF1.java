package aladdin.capi.ansi.derive;
import aladdin.*; 
import aladdin.math.*;
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Псевдослучайная функция маскирования MGF1
///////////////////////////////////////////////////////////////////////////
public class MGF1 extends PRF
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
	// алгоритм хэширования
	private final Hash hashAlgorithm;
	
	// конструктор
	public MGF1(Hash hashAlgorithm) 
    {
        // сохранить переданные параметры
        this.hashAlgorithm = RefObject.addRef(hashAlgorithm); 
    }    
    // освободить ресурсы 
    @Override protected void onClose() throws IOException 
    { 
        // освободить ресурсы 
        RefObject.release(hashAlgorithm); super.onClose();            
    }
	// сгенерировать блок данных
	@Override public void generate(byte[] key, byte[] random, 
        byte[] buffer, int offset, int deriveSize) throws IOException
	{
        // проверить наличие размера
        if (deriveSize < 0) throw new IllegalStateException(); 
        
		// выделить память для аргументов хэширования
		byte[] C = new byte[key.length + 4]; System.arraycopy(key, 0, C, 0, key.length);  
			
        // выделить буфер требуемого размера
        int hLen = hashAlgorithm.hashSize();
        
		// для всех блоков
		for (int cb = 0; cb < deriveSize; cb += hLen)
		{
			// закодировать номер шага
			Convert.fromInt32(cb / hLen, ENDIAN, C, key.length);  

			// захэшировать данные
			byte[] hash = hashAlgorithm.hashData(C, 0, C.length); 
				
            // определить копируемый размер
            int length = (hLen < deriveSize - cb) ? hLen : deriveSize - cb; 
            
			// скопировать хэш-значение
			System.arraycopy(hash, 0, buffer, offset + cb, length); 
		}
	}
}

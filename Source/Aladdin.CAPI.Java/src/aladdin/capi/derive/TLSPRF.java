package aladdin.capi.derive;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.util.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Псевдослучайная функция TLS
///////////////////////////////////////////////////////////////////////////
public class TLSPRF extends PRF
{
    // алгоритм вычисления имитовставки
    private final Mac macAlgorithm; private final byte[] label; 
	
    // конструктор
    public TLSPRF(Mac macAlgorithm, byte[] label) 
    { 
        // сохранить переданные параметры
        this.macAlgorithm = RefObject.addRef(macAlgorithm); this.label = label; 
    }    
    // освободить ресурсы 
    @Override
    protected void onClose() throws IOException
    { 
        // освободить ресурсы 
        RefObject.release(macAlgorithm); super.onClose();
    }
    // тип ключа
    @Override public SecretKeyFactory keyFactory() { return macAlgorithm.keyFactory(); } 
    
    // сгенерировать блок данных
    @Override
    public void generate(byte[] keyValue, byte[] seed, byte[] buffer, 
        int offset, int deriveSize) throws IOException
    {
        // проверить наличие размера
        if (deriveSize < 0) throw new IllegalStateException(); 
        
        // добавить метку в случайные данные
        seed = Array.concat(label, seed); 

        // указать начальные условия
        byte[] A = seed; int blockSize = macAlgorithm.macSize();
        
        // указать используемый ключ
        try (ISecretKey key = macAlgorithm.keyFactory().create(keyValue))
        {
            // для всех блоков
            for (int cb = 0; cb < deriveSize; cb += blockSize)
            {
                // вычислить имитовставку
                A = macAlgorithm.macData(key, A, 0, A.length); 

                // выполнить конкатенацию данных
                byte[] data = Array.concat(A, seed); 

                // вычислить имитовставку
                byte[] mac = macAlgorithm.macData(key, data, 0, data.length); 

                // определить используемый размер 
                int length = (blockSize < deriveSize - cb) ? blockSize : deriveSize - cb; 

                // скопировать имитовставку
                System.arraycopy(mac, 0, buffer, offset + cb, length); 
            }
        }
        // обработать неожидаемое исключение
        catch (InvalidKeyException e) { throw new IOException(e); } 
	}
}

package aladdin.capi.mode;
import aladdin.*; 
import aladdin.capi.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Режим CTR
///////////////////////////////////////////////////////////////////////////////
public class CTR extends BlockMode
{
    // алгоритм шифрования блока и параметры режима
    private final Cipher engine; private final CipherMode.CTR parameters; 
    
    // конструктор
	public CTR(Cipher engine, CipherMode.CTR parameters)
	{ 
        // сохранить переданные параметры
        super(PaddingMode.NONE); this.parameters = parameters; 
        
        // проверить корректность данных
        if (parameters.iv().length > engine.blockSize()) 
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException(); 
        }
        // сохранить переданные параметры
        this.engine = RefObject.addRef(engine); 
	}
    // деструктор
    @Override protected void onClose() throws IOException 
    { 
        // освободить выделенные ресурсы
        RefObject.release(engine); super.onClose();
    } 
    // режим шифрования 
	@Override public final CipherMode.CTR mode() { return parameters; }
    
    // тип ключа
	@Override public final SecretKeyFactory keyFactory() { return engine.keyFactory(); }
    // размер ключа
	@Override public final int[] keySizes() { return engine.keySizes(); }
    // размер блока
	@Override public final int blockSize() 
    { 
    	// получить размер блока алгоритма
		int blockSize = parameters.blockSize(); 
            
        // вернуть размер блока алгоритма
        return (blockSize > 0) ? blockSize : engine.blockSize(); 
    }
    // преобразование зашифрования
    @Override protected aladdin.capi.Transform createEncryption(ISecretKey key) 
        throws IOException, InvalidKeyException 
    { 
        // преобразование зашифрования
        return new Transform(engine, key, parameters); 
    }
    // преобразование расшифрования
    @Override protected aladdin.capi.Transform createDecryption(ISecretKey key) 
        throws IOException, InvalidKeyException 
    { 
        // преобразование расшифрования
        return new Transform(engine, key, parameters); 
    }
    // алгоритм шифрования блока
	protected final Cipher engine() { return engine; }   
    
    ///////////////////////////////////////////////////////////////////////////////
    // Режим преобразования CTR
    ///////////////////////////////////////////////////////////////////////////////
    public static class Transform extends BlockTransform
    {
        // алгоритм шифрования блока и параметры алгоритма
        private final Cipher engine; private final CipherMode.CTR parameters;
        
        // ключ шифрования, преобразование блока данных и вектор инициализации
        private final ISecretKey key; protected aladdin.capi.Transform encryption; private byte[] iv;

        // конструктор
        public Transform(Cipher engine, ISecretKey key, CipherMode.CTR parameters) 
        {
            // сохранить переданные параметры
            super(engine.blockSize()); this.engine = RefObject.addRef(engine); 

            // сохранить параметры 
            this.key = RefObject.addRef(key); this.parameters = parameters; encryption = null; 
        }
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException  
        { 
            // освободить выделенные ресурсы
            RefObject.release(encryption); RefObject.release(key);
            
            // освободить выделенные ресурсы
            RefObject.release(engine); super.onClose(); 
        } 
        // параметры шифрования
        public final CipherMode.CTR parameters() { return parameters; }
        
        // инициализировать алгоритм
        @Override public void init() throws IOException
        { 
            // выполнить инициализацию
            iv = new byte[engine.blockSize()]; resetKey(key); 

            // скопировать синхропосылку
            System.arraycopy(parameters.iv(), 0, iv, 0, parameters.iv().length); 
        }  
        @Override protected void update(
            byte[] data, int dataOff, byte[] buf, int bufOff) throws IOException
        {
            // выделить вспомогательный буфер
            byte[] copy = new byte[engine.blockSize()];

            // зашифровать регистр, увеличить регистр 
            encryption.update(iv, 0, copy.length, copy, 0); increment(iv);

            // для всех байтов
            for (int j = 0; j < blockSize(); j++) 
            {
                // выполнить поразрядное сложение
                buf[bufOff + j] = (byte)(data[dataOff + j] ^ copy[j]); 
            }
        }
        // выполнить инкремент регистра обратной связи
        protected void increment(byte[] iv)
        {
            // определить последний инкрементируемый байт
            int limit = iv.length - parameters.counterSize(); 
            
            // для всех разрядов регистра
            for (int i = iv.length - 1; i >= limit; i--)
            {
                // увеличить разряд регистра
                iv[i] = (byte)(iv[i] + 1); if (iv[i] != 0) break; 
            }
        }
        // переустановить ключ
        protected final void resetKey(ISecretKey key) throws IOException
        {
            // освободить выделенные ресурсы
            RefObject.release(encryption); encryption = null;  
            try {
                // создать алгоритм зашифрования блока
                encryption = engine.createEncryption(key, PaddingMode.NONE); 

                // выполнить инициализацию
                encryption.init();
            }
            // обработать неожидаемую ошибку
            catch (InvalidKeyException e) { throw new IOException(e); }
        }  
        // регистр обратной связи
        protected final byte[] iv() { return iv; }
    }
}

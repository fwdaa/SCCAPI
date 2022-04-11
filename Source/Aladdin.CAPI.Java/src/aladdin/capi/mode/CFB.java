package aladdin.capi.mode;
import aladdin.*; 
import aladdin.capi.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Режим зашифрования CFB
///////////////////////////////////////////////////////////////////////////////
public class CFB extends BlockMode
{
    // алгоритм шифрования блока и параметры режима
    private final Cipher engine; private final CipherMode.CFB parameters; 
    
    // конструктор
	public CFB(Cipher engine, CipherMode.CFB parameters)
	{ 
        // сохранить переданные параметры
        super(PaddingMode.NONE); this.parameters = parameters; 
        
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
	@Override public final CipherMode.CFB mode() { return parameters; }
    
    // тип ключа
	@Override public final SecretKeyFactory keyFactory() { return engine.keyFactory(); }
    // размер блока
	@Override public final int blockSize() 
    { 
    	// получить размер блока алгоритма
		int blockSize = parameters.blockSize(); 
            
        // вернуть размер блока алгоритма
        return (blockSize > 0) ? blockSize : engine.blockSize(); 
    }
    // преобразование зашифрования
    @Override protected Transform createEncryption(ISecretKey key) 
        throws IOException, InvalidKeyException 
    { 
        // преобразование зашифрования
        return new Encryption(engine, key, parameters); 
    }
    // преобразование расшифрования
    @Override protected Transform createDecryption(ISecretKey key) 
        throws IOException, InvalidKeyException 
    { 
        // преобразование расшифрования
        return new Decryption(engine, key, parameters); 
    }
    // алгоритм шифрования блока
	protected final Cipher engine() { return engine; }   
    
    ///////////////////////////////////////////////////////////////////////////////
    // Режим зашифрования CFB
    ///////////////////////////////////////////////////////////////////////////////
    public static class Encryption extends BlockTransform
    {
        // алгоритм шифрования блока и параметры алгоритма
        private final Cipher engine; private final CipherMode.CFB parameters;
        
        // ключ шифрования, преобразование блока данных и вектор инициализации
        private final ISecretKey key; private Transform encryption; private byte[] iv;

        // конструктор
        public Encryption(Cipher engine, ISecretKey key, CipherMode.CFB parameters) 
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
        public final CipherMode.CFB parameters() { return parameters; }
        
        // инициализировать алгоритм
        @Override public void init() throws IOException
        { 
            // выполнить инициализацию
            iv = parameters.iv().clone(); resetKey(key); 
        }  
        @Override protected void update(
            byte[] data, int dataOff, byte[] buf, int bufOff) throws IOException
        {
            // выделить вспомогательный буфер
            byte[] encrypted = new byte[engine.blockSize()]; 

            // зашифровать регистр обратной связи
            encryption.update(iv, 0, encrypted.length, encrypted, 0);

            // сложить результат шифрования с исходными данными
            for (int j = 0; j < blockSize(); j++)
            {
                // сложить результат шифрования с исходными данными
                buf[bufOff + j] = (byte)(data[dataOff + j] ^ encrypted[j]);
            }
            // сдвинуть регистр обратной связи
            System.arraycopy(iv, blockSize(), iv, 0, iv.length - blockSize()); 

            // регистр = зашифрованный текст
            System.arraycopy(buf, bufOff, iv, iv.length - encrypted.length, encrypted.length); 
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
    ///////////////////////////////////////////////////////////////////////////////
    // Режим расшифрования CFB
    ///////////////////////////////////////////////////////////////////////////////
    public static class Decryption extends BlockTransform
    {
        // алгоритм шифрования блока и параметры алгоритма
        private final Cipher engine; private final CipherMode.CFB parameters;
        
        // ключ шифрования, преобразование блока данных и вектор инициализации
        private final ISecretKey key; private Transform encryption; private byte[] iv;

        // конструктор
        public Decryption(Cipher engine, ISecretKey key, CipherMode.CFB parameters) 
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
        public final CipherMode.CFB parameters() { return parameters; }
        
        // инициализировать алгоритм
        @Override public void init() throws IOException
        { 
            // выполнить инициализацию
            iv = parameters.iv().clone(); resetKey(key); 
        }  
        @Override protected void update(
            byte[] data, int dataOff, byte[] buf, int bufOff) throws IOException
        {
            // выделить вспомогательный буфер
            byte[] encrypted = new byte[engine.blockSize()]; 

            // зашифровать регистр обратной связи
            encryption.update(iv, 0, encrypted.length, encrypted, 0);

            // сдвинуть регистр обратной связи
            System.arraycopy(iv, blockSize(), iv, 0, iv.length - blockSize()); 

            // регистр = исходный зашифрованный текст
            System.arraycopy(data, dataOff, iv, iv.length - blockSize(), blockSize()); 

            // сложить результат шифрования с исходными данными
            for (int j = 0; j < blockSize(); j++)
            {
                // сложить результат шифрования с исходными данными
                buf[bufOff + j] = (byte)(data[dataOff + j] ^ encrypted[j]);
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

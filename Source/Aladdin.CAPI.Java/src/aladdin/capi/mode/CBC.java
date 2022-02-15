package aladdin.capi.mode;
import aladdin.*; 
import aladdin.capi.*;
import java.security.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Режим CBC
///////////////////////////////////////////////////////////////////////////////
public class CBC extends BlockMode
{
    // алгоритм шифрования блока и параметры режима
    private final Cipher engine; private final CipherMode.CBC parameters; 

    // конструктор
	public CBC(Cipher engine, CipherMode.CBC parameters, PaddingMode padding) 
    { 
        // сохранить переданные параметры
        super(padding); this.parameters = parameters; 
        
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
	@Override public final CipherMode.CBC mode() { return parameters; }
    
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
    // Режим зашифрования CBC
    ///////////////////////////////////////////////////////////////////////////////
    public static class Encryption extends BlockTransform
    {
        // алгоритм шифрования блока и параметры алгоритма
        private final Cipher engine; private final CipherMode.CBC parameters;
        
        // ключ шифрования, преобразование блока данных и вектор инициализации
        private final ISecretKey key; private Transform encryption; private byte[] iv;

        // конструктор
        public Encryption(Cipher engine, ISecretKey key, CipherMode.CBC parameters) 
        {
            // сохранить переданные параметры
            super(engine.blockSize()); this.engine = RefObject.addRef(engine); 

            // сохранить параметры 
            this.key = RefObject.addRef(key); this.parameters = parameters; encryption = null; 
        }
        // конструктор
        public Encryption(Cipher engine, ISecretKey key, byte[] iv) 
            throws IOException, InvalidKeyException
        {
            // сохранить переданные параметры
            this(engine, key, new CipherMode.CBC(iv));  
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
        public final CipherMode.CBC parameters() { return parameters; }
        
        // инициализировать алгоритм
        @Override public void init() throws IOException
        { 
            // выполнить инициализацию
            iv = parameters.iv().clone(); resetKey(key); 
        }  
        @Override protected void update(
            byte[] data, int dataOff, byte[] buf, int bufOff) throws IOException
        {
            // регистр ^= расшифрованный текст 
            for (int j = 0; j < blockSize(); j++) iv[j] ^= data[dataOff + j];

            // зашифровать регистр 
            encryption.update(iv, 0, engine.blockSize(), buf, bufOff);

            // выполнить сдвиг регистра
            System.arraycopy(iv, blockSize(), iv, 0, iv.length - blockSize()); 

            // сохранить зашифрованные данные в регистре
            System.arraycopy(buf, bufOff, iv, iv.length - blockSize(), blockSize()); 
        }
        @Override public int finish(
            byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // проверить корректность данных
            if ((dataLen % blockSize()) != 0) throw new IOException();

            // преобразовать полные блоки
            update(data, dataOff, dataLen, buf, bufOff); return dataLen; 
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
    // Режим расшифрования CBC
    ///////////////////////////////////////////////////////////////////////////////
    public static class Decryption extends BlockTransform
    {
        // алгоритм шифрования блока и параметры алгоритма
        private final Cipher engine; private final CipherMode.CBC parameters;
        
        // ключ шифрования, преобразование блока данных и вектор инициализации
        private final ISecretKey key; private Transform decryption; private byte[] iv;

        // конструктор
        public Decryption(Cipher engine, ISecretKey key, CipherMode.CBC parameters) 
        {
            // сохранить переданные параметры
            super(engine.blockSize()); this.engine = RefObject.addRef(engine); 

            // сохранить параметры 
            this.key = RefObject.addRef(key); this.parameters = parameters; decryption = null; 
        }
        // конструктор
        public Decryption(Cipher engine, ISecretKey key, byte[] iv) 
            throws IOException, InvalidKeyException
        {
            // сохранить переданные параметры
            this(engine, key, new CipherMode.CBC(iv));  
        }
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException  
        { 
            // освободить выделенные ресурсы
            RefObject.release(decryption); RefObject.release(key);
            
            // освободить выделенные ресурсы
            RefObject.release(engine); super.onClose(); 
        } 
        // параметры шифрования
        public final CipherMode.CBC parameters() { return parameters; }
        
        // инициализировать алгоритм
        @Override public void init() throws IOException
        { 
            // выполнить инициализацию
            iv = parameters.iv().clone(); resetKey(key); 
        }  
        @Override protected void update(
            byte[] data, int dataOff, byte[] buf, int bufOff) throws IOException
        {
            // выделить вспомогательный блок
            byte[] copy = new byte[blockSize()];

            // сохранить зашифрованный текст
            System.arraycopy(data, dataOff, copy, 0, copy.length);

            // расшифровать зашифрованный текст
            decryption.update(data, dataOff, engine.blockSize(), buf, bufOff);

            // расшифрованный текст ^= регистр  
            for (int j = 0; j < copy.length; j++) buf[bufOff + j] ^= iv[j];

            // выполнить сдвиг регистра
            System.arraycopy(iv, copy.length, iv, 0, iv.length - copy.length);

            // сохранить зашифрованный текст в регистре
            System.arraycopy(copy, 0, iv, iv.length - copy.length, copy.length); 
        }
        @Override public int finish(
            byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // проверить корректность данных
            if ((dataLen % blockSize()) != 0) throw new IOException();

            // преобразовать полные блоки
            update(data, dataOff, dataLen, buf, bufOff); return dataLen; 
        }
        // переустановить ключ
        protected final void resetKey(ISecretKey key) throws IOException
        {
            // освободить выделенные ресурсы
            RefObject.release(decryption); decryption = null;  
            try {
                // создать алгоритм расшифрования блока
                decryption = engine.createDecryption(key, PaddingMode.NONE); 

                // выполнить инициализацию
                decryption.init();
            }
            // обработать неожидаемую ошибку
            catch (InvalidKeyException e) { throw new IOException(e); }
        }  
        // регистр обратной связи
        protected final byte[] iv() { return iv; }
    }
}

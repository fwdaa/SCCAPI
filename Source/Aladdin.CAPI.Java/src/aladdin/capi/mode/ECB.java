package aladdin.capi.mode;
import aladdin.*; 
import aladdin.capi.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Режим ECB
///////////////////////////////////////////////////////////////////////////////
public class ECB extends BlockMode
{        
    // алгоритм шифрования блока
    private final Cipher engine; 

    // конструктор
	public ECB(Cipher engine, PaddingMode padding) 
    { 
        // сохранить переданные параметры
        super(padding); this.engine = RefObject.addRef(engine); 
    }
    // деструктор
    @Override protected void onClose() throws IOException 
    { 
        // освободить выделенные ресурсы
        RefObject.release(engine); super.onClose();
    } 
    // режим шифрования 
	@Override public CipherMode mode() { return new CipherMode.ECB(); }
    
    // тип ключа
	@Override public final SecretKeyFactory keyFactory() { return engine.keyFactory(); }
    // размер ключа
	@Override public final int[] keySizes() { return engine.keySizes(); }
    // размер блока
	@Override public final int blockSize() { return engine.blockSize(); }
    
    // преобразование зашифрования
    @Override protected Transform createEncryption(ISecretKey key) 
        throws IOException, InvalidKeyException 
    { 
        // преобразование зашифрования
        return new Encryption(engine, key); 
    }
    // преобразование расшифрования
    @Override protected Transform createDecryption(ISecretKey key) 
        throws IOException, InvalidKeyException 
    { 
        // преобразование расшифрования
        return new Decryption(engine, key); 
    }
    // алгоритм шифрования блока
	protected final Cipher engine() { return engine; }   
    
    ///////////////////////////////////////////////////////////////////////////////
    // Режим зашифрования ECB
    ///////////////////////////////////////////////////////////////////////////////
    public static class Encryption extends BlockTransform
    {
        // алгоритм шифрования блока, ключ шифрования и преобразование блока данных
        private final Cipher engine; private final ISecretKey key; private Transform encryption;

        // конструктор
        public Encryption(Cipher engine, ISecretKey key) 
        { 
            // создать алгоритм зашифрования блока
            super(engine.blockSize()); this.engine = RefObject.addRef(engine);
            
            // сохранить переданные параметры
            this.key = RefObject.addRef(key); encryption = null; 
        } 
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException  
        { 
            // освободить выделенные ресурсы
            RefObject.release(encryption); RefObject.release(key); 
            
            // освободить выделенные ресурсы
            RefObject.release(engine); super.onClose(); 
        } 
        // инициализировать алгоритм
        @Override public void init() throws IOException { resetKey(key); }  
        
        @Override protected void update( 
            byte[] data, int dataOff, byte[] buf, int bufOff) throws IOException
        {
            // зашифровать полный блок
            encryption.update(data, dataOff, engine.blockSize(), buf, bufOff); 
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
    }
    ///////////////////////////////////////////////////////////////////////////////
    // Режим расшифрования ECB
    ///////////////////////////////////////////////////////////////////////////////
    public static class Decryption extends BlockTransform
    {
        // алгоритм шифрования блока, ключ шифрования и преобразование блока данных
        private final Cipher engine; private final ISecretKey key; private Transform decryption;

        // конструктор
        public Decryption(Cipher engine, ISecretKey key) 
        { 
            // создать алгоритм зашифрования блока
            super(engine.blockSize()); this.engine = RefObject.addRef(engine);
            
            // сохранить переданные параметры
            this.key = RefObject.addRef(key); decryption = null; 
        } 
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException  
        { 
            // освободить выделенные ресурсы
            RefObject.release(decryption); RefObject.release(key); 
            
            // освободить выделенные ресурсы
            RefObject.release(engine); super.onClose(); 
        } 
        // инициализировать алгоритм
        @Override public void init() throws IOException { resetKey(key); }  
        
        @Override protected void update( 
            byte[] data, int dataOff, byte[] buf, int bufOff) throws IOException
        {
            // расшифровать полный блок
            decryption.update(data, dataOff, engine.blockSize(), buf, bufOff); 
        }
        @Override public int finish(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff) throws IOException
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
    }
}

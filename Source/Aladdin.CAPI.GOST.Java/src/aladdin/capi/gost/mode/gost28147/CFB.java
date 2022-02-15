package aladdin.capi.gost.mode.gost28147;
import aladdin.*; 
import aladdin.capi.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Режим CFB
///////////////////////////////////////////////////////////////////////////////
public class CFB extends aladdin.capi.mode.CFB
{
    // режим смены ключа
    private final KeyDerive keyMeshing;
    
    // конструктор
	public CFB(Cipher engine, CipherMode.CFB parameters, KeyDerive keyMeshing)
	{ 
        // сохранить переданные параметры
        super(engine, parameters); this.keyMeshing = RefObject.addRef(keyMeshing); 
	}
    // конструктор
	public CFB(Cipher engine, CipherMode.CFB parameters)
	{ 
        // сохранить переданные параметры
        super(engine, parameters); this.keyMeshing = null; 
	}
    // деструктор
    @Override protected void onClose() throws IOException    
    { 
        // освободить ресурсы
        RefObject.release(keyMeshing); super.onClose();
    }
    // преобразование зашифрования
    @Override protected Transform createEncryption(ISecretKey key) 
    { 
        // преобразование зашифрования
        return new Encryption(engine(), keyMeshing, key, mode()); 
    }
    // преобразование расшифрования
    @Override protected Transform createDecryption(ISecretKey key) 
    { 
        // преобразование расшифрования
        return new Decryption(engine(), keyMeshing, key, mode()); 
    }
    ///////////////////////////////////////////////////////////////////////////////
    // Режим зашифрования CFB
    ///////////////////////////////////////////////////////////////////////////////
    public static class Encryption extends aladdin.capi.mode.CFB.Encryption
    {
        // алгоритм смены ключа и размер смены ключа
        private final KeyDerive keyMeshing; private final int N;
        // текущий ключ и накопленный размер
        private ISecretKey currentKey; private int length; 

        // конструктор
        public Encryption(Cipher engine, KeyDerive keyMeshing, ISecretKey key, CipherMode.CFB parameters) 
        { 
            // сохранить переданные параметры
            super(engine, key, parameters); currentKey = RefObject.addRef(key); 
            
            // сохранить переданные параметры
            this.keyMeshing = RefObject.addRef(keyMeshing); 
            
            // указать размер смены ключа
            N = (keyMeshing != null) ? 1024 : 0; 
        } 
        // конструктор
        public Encryption(Cipher engine, ISecretKey key, CipherMode.CFB parameters) 
        { 
            // смена ключа отсутствует
            super(engine, key, parameters); keyMeshing = null; N = 0; 
            
            // сохранить переданные параметры
            currentKey = RefObject.addRef(key); 
        } 
        // освободить ресурсы
        @Override protected void onClose() throws IOException    
        {
            // освободить ресурсы
            RefObject.release(currentKey);
            
            // освободить ресурсы
            RefObject.release(keyMeshing); super.onClose();
        }
        // инициализировать алгоритм
        @Override public void init() throws IOException { super.init(); length = 0; }
        
        @Override protected void update( 
            byte[] data, int dataOff, byte[] buf, int bufOff) throws IOException
        {
            // обработать полный блок
            super.update(data, dataOff, buf, bufOff); 
            
            // увеличить размер данных
            length += blockSize(); if (N == 0 || (length % N) != 0) return; 

            // изменить значение ключа
            try (ISecretKey key = keyMeshing.deriveKey(currentKey, iv(), currentKey.keyFactory(), 32))
            {
                // переустановить ключ
                if (key != currentKey) resetKey(key); 

                // сохранить новый текущий ключ
                RefObject.release(currentKey); currentKey = RefObject.addRef(key); 
            }
            // обработать неожидаемое исключение
            catch (InvalidKeyException e) { throw new RuntimeException(e); }
        }
    }
    ///////////////////////////////////////////////////////////////////////////////
    // Режим расшифрования CFB
    ///////////////////////////////////////////////////////////////////////////////
    public static class Decryption extends aladdin.capi.mode.CFB.Decryption
    {
        // алгоритм смены ключа и размер смены ключа
        private final KeyDerive keyMeshing; private final int N;
        // текущий ключ и накопленный размер
        private ISecretKey currentKey; private int length; 
        
        // конструктор
        public Decryption(Cipher engine, KeyDerive keyMeshing, ISecretKey key, CipherMode.CFB parameters) 
        { 
            // сохранить переданные параметры
            super(engine, key, parameters); currentKey = RefObject.addRef(key); 
            
            // сохранить переданные параметры
            this.keyMeshing = RefObject.addRef(keyMeshing); 

            // указать размер смены ключа
            N = (keyMeshing != null) ? 1024 : 0; 
        } 
        // конструктор
        public Decryption(Cipher engine, ISecretKey key, CipherMode.CFB parameters) 
        { 
            // смена ключа отсутствует
            super(engine, key, parameters); keyMeshing = null; N = 0; 
            
            // сохранить переданные параметры
            currentKey = RefObject.addRef(key); 
        } 
        // освободить ресурсы
        @Override protected void onClose() throws IOException    
        {
            // освободить ресурсы
            RefObject.release(currentKey);
            
            // освободить ресурсы
            RefObject.release(keyMeshing); super.onClose();
        }
        // инициализировать алгоритм
        @Override public void init() throws IOException { super.init(); length = 0; }
        
        @Override protected void update( 
            byte[] data, int dataOff, byte[] buf, int bufOff) throws IOException
        {
            // обработать полный блок
            super.update(data, dataOff, buf, bufOff); 
            
            // увеличить размер данных
            length += blockSize(); if (N == 0 || (length % N) != 0) return; 

            // изменить значение ключа
            try (ISecretKey key = keyMeshing.deriveKey(currentKey, iv(), currentKey.keyFactory(), 32))
            {
                // переустановить ключ
                if (key != currentKey) resetKey(key); 

                // сохранить новый текущий ключ
                RefObject.release(currentKey); currentKey = RefObject.addRef(key); 
            }
            // обработать неожидаемое исключение
            catch (InvalidKeyException e) { throw new RuntimeException(e); }
        }
    }
}
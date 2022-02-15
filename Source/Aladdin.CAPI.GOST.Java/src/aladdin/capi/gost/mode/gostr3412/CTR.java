package aladdin.capi.gost.mode.gostr3412;
import aladdin.*; 
import aladdin.capi.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Режим CTR
///////////////////////////////////////////////////////////////////////////////
public class CTR extends aladdin.capi.mode.CTR
{
    // режим смены ключа и размер смены ключа
    private final KeyDerive keyMeshing; private final int N; 
    
    // конструктор
	public CTR(Cipher engine, CipherMode.CTR parameters, KeyDerive keyMeshing, int N)
	{ 
        // сохранить переданные параметры
        super(engine, parameters); this.N = N; 
        
        // сохранить переданные параметры
        this.keyMeshing = RefObject.addRef(keyMeshing); 
	}
    // конструктор
	public CTR(Cipher engine, CipherMode.CTR parameters)
	{ 
        // сохранить переданные параметры
        super(engine, parameters); this.keyMeshing = null; N = 0;  
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
        return new Transform(engine(), keyMeshing, N, key, mode()); 
    }
    // преобразование расшифрования
    @Override protected Transform createDecryption(ISecretKey key) 
    { 
        // преобразование расшифрования
        return new Transform(engine(), keyMeshing, N, key, mode()); 
    }
    ///////////////////////////////////////////////////////////////////////////////
    // Режим шифрования CFB
    ///////////////////////////////////////////////////////////////////////////////
    public static class Transform extends aladdin.capi.mode.CTR.Transform
    {
        // алгоритм смены ключа и размер смены ключа
        private final KeyDerive keyMeshing; private final int N;
        // текущий ключ и накопленный размер
        private ISecretKey currentKey; private int length; 

        // конструктор
        public Transform(Cipher engine, KeyDerive keyMeshing, int N, 
            ISecretKey key, CipherMode.CTR parameters) 
        { 
            // сохранить переданные параметры
            super(engine, key, parameters); this.N = N; 
            
            // проверить корректность параметров
            if ((N % engine.blockSize()) != 0) throw new IllegalArgumentException(); 
            
            // сохранить переданные параметры
            currentKey = RefObject.addRef(key); 
            
            // сохранить переданные параметры
            this.keyMeshing = RefObject.addRef(keyMeshing); 
        } 
        // конструктор
        public Transform(Cipher engine, ISecretKey key, CipherMode.CTR parameters) 
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
                resetKey(key); RefObject.release(currentKey); currentKey = RefObject.addRef(key); 
            }
            // обработать неожидаемое исключение
            catch (InvalidKeyException e) { throw new RuntimeException(e); }
        }
    }
}

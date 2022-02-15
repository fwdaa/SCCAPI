package aladdin.capi.gost.mode.gost28147;
import aladdin.capi.gost.engine.GOST28147;
import aladdin.*;
import aladdin.math.*; 
import aladdin.capi.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Режим CTR
//////////////////////////////////////////////////////////////////////////////
public class CTR extends aladdin.capi.mode.CTR
{
    // режим смены ключа
    private final KeyDerive keyMeshing;
    
    // конструктор
	public CTR(Cipher engine, CipherMode.CTR parameters, KeyDerive keyMeshing)
	{ 
        // сохранить переданные параметры
        super(engine, parameters); this.keyMeshing = RefObject.addRef(keyMeshing); 
	}
    // конструктор
	public CTR(Cipher engine, CipherMode.CTR parameters)
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
    @Override protected aladdin.capi.Transform createEncryption(ISecretKey key) 
    { 
        // преобразование зашифрования
        return new Transform(engine(), keyMeshing, key, mode()); 
    }
    // преобразование расшифрования
    @Override protected aladdin.capi.Transform createDecryption(ISecretKey key) 
    { 
        // преобразование расшифрования
        return new Transform(engine(), keyMeshing, key, mode()); 
    }
    ///////////////////////////////////////////////////////////////////////////////
    // Режим преобразования CTR
    ///////////////////////////////////////////////////////////////////////////////
    public static class Transform extends aladdin.capi.mode.CTR.Transform
    {
        // алгоритм смены ключа и размер смены ключа
        private final KeyDerive keyMeshing; private final int N;
        // текущий ключ и накопленный размер
        private ISecretKey currentKey; private int length; 

        // конструктор
        public Transform(Cipher engine, KeyDerive keyMeshing, ISecretKey key, CipherMode.CTR parameters) 
        { 
            // сохранить переданные параметры
            super(engine, key, parameters); currentKey = RefObject.addRef(key); 
            
            // сохранить переданные параметры
            this.keyMeshing = RefObject.addRef(keyMeshing); 
            
            // указать размер смены ключа
            N = (keyMeshing != null) ? 1024 : 0; 
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
        @Override public void init() throws IOException 
        { 
            // обнулить размер данных
            super.init(); length = 0; 
            
            // зашифровать синхропосылку
            encryption.update(iv(), 0, iv().length, iv(), 0);
        }
        @Override protected void update(
            byte[] data, int dataOff, byte[] buf, int bufOff) throws IOException 
        {
            // выделить вспомогательный буфер
            byte[] copy = new byte[blockSize()]; increment(iv());

            // зашифровать регистр, увеличить регистр 
            encryption.update(iv(), 0, copy.length, copy, 0); 

            // для всех байтов
            for (int j = 0; j < blockSize(); j++) 
            {
                // выполнить поразрядное сложение
                buf[bufOff + j] = (byte)(data[dataOff + j] ^ copy[j]); 
            }
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
        @Override protected void increment(byte[] iv)
        {
            // фиксированные константы
            int C1 = 0x01010104; int C2 = 0x01010101;

            // извлечь обрабатываемый блок
            int N2 = Convert.toInt32(iv, 0, GOST28147.ENDIAN); 
            int N1 = Convert.toInt32(iv, 4, GOST28147.ENDIAN); 

            // добавить фиксированные константы
            N2 = N2 + C2; N1 = N1 + C1; if (N1 >= 0 && N1 < C1) N1++;

            // вернуть обработанный блок
            Convert.fromInt32(N2, GOST28147.ENDIAN, iv, 0); 
            Convert.fromInt32(N1, GOST28147.ENDIAN, iv, 4); 
        }
    }
}

package aladdin.capi.mode;
import aladdin.*; 
import aladdin.capi.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Поточный алгоритм шифрования на основе 1-битного OFB
///////////////////////////////////////////////////////////////////////////////
public class OFB1 extends Cipher
{
    // блочный алгоритм шифрования и синхропосылка
    private final Cipher engine; private final byte[] iv; 
    
    // конструктор
    public OFB1(Cipher engine, byte[] iv) 
    { 
        // сохранить переданные параметры
        this.engine = RefObject.addRef(engine); this.iv = iv;
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException 
    { 
        // освободить выделенные ресурсы
        RefObject.release(engine); super.onClose();
    }
    // тип ключа
	@Override public final SecretKeyFactory keyFactory() { return engine.keyFactory(); }

    @Override public Transform createEncryption(ISecretKey key) 
        throws IOException, InvalidKeyException
    {
        // создать преобразование зашифрования
        return new Transform(engine, key, iv); 
    }
    @Override public Transform createDecryption(ISecretKey key) 
        throws IOException, InvalidKeyException
    {
        // создать преобразование расшифрования
        return new Transform(engine, key, iv); 
    }
    ////////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования
    ////////////////////////////////////////////////////////////////////////////
    public static class Transform extends aladdin.capi.Transform
    {
        // зашифрование блока данных и размер блока
        private final aladdin.capi.Transform encryption; private final int blockSize; 	
        
        // вектор инициализации
        private final byte[] initIV; private byte[] currentIV;
        
        // конструктор
        public Transform(Cipher engine, ISecretKey key, byte[] iv) 
            throws IOException, InvalidKeyException
        {
            // создать преобразование зашифрования
            encryption = engine.createEncryption(key, PaddingMode.NONE); 
            
            // сохранить синхропосылку
            initIV = iv.clone(); blockSize = engine.blockSize(); 
        }
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException 
        { 
            // освободить выделенные ресурсы
            RefObject.release(encryption); super.onClose();
        }
        // инициализировать алгоритм
        @Override public void init() throws IOException
        { 
            // инициализировать алгоритм
            encryption.init(); currentIV = initIV.clone(); 
        } 
        // преобразовать данные
        @Override public int update(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // скопировать исходные данные
            System.arraycopy(data, dataOff, buf, bufOff, dataLen);
            
            // выделить память для результата шифрования
            byte[] encrypted = new byte[currentIV.length]; 
            
            // для всех битов байтов
            for (int i = 0; i < dataLen; i++) for (int j = 0; j < 8; j++)
            {
                // зашифровать регистр обратной связи
                encryption.update(currentIV, 0, blockSize, encrypted, 0);
                    
                // извлечь старший бит
                int bit = (encrypted[0] & (byte)0x80) >>> 7; 
                    
                // сложить результат шифрования
                buf[bufOff + i] ^= bit << (7 - j); currentIV[0] <<= 1;
                    
                // для всех байтов регистра обратной связи
                for (int k = 0; k < currentIV.length - 1; k++)
                {
                    // выполнить сдвиг байта на одну позицию
                    currentIV[k] |= (currentIV[k + 1] >>> 7); currentIV[k + 1] <<= 1;
                }
                // установить младший бит
                currentIV[currentIV.length - 1] |= bit; 
            }
            return dataLen; 
        }
        // завершить преобразование
        @Override public int finish(byte[] data, int dataOff, int dataLen, 
            byte[] buf, int bufOff) throws IOException
        {
            // выполнить преобразование
            return update(data, dataOff, dataLen, buf, bufOff); 
        }
    }
}

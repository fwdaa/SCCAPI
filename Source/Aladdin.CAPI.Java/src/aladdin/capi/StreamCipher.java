package aladdin.capi;
import aladdin.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Поточный алгоритм шифрования на основе маскирующей последовательности
///////////////////////////////////////////////////////////////////////////////
public abstract class StreamCipher extends Cipher
{
    @Override protected Transform createEncryption(ISecretKey key) 
        throws InvalidKeyException, IOException
    {
        // создать алгоритм генерации последовательности
        try (IRand algorithm = createPRF(key))
        {
            // создать преобразование шифрования
            return new Transform(algorithm); 
        }
    }
    @Override protected Transform createDecryption(ISecretKey key) 
        throws InvalidKeyException, IOException
    {
        // создать алгоритм генерации последовательности
        try (IRand algorithm = createPRF(key))
        {
            // создать преобразование шифрования
            return new Transform(algorithm); 
        }
    }
    // указать алгоритм генерации последовательности
    protected abstract IRand createPRF(ISecretKey key) throws InvalidKeyException; 
    
    ///////////////////////////////////////////////////////////////////////
    // Преобразования шифрования 
    ///////////////////////////////////////////////////////////////////////
    public static class Transform extends aladdin.capi.Transform
    {
        // алгоритм генерации последовательности
        private final IRand algorithm; 
        
        // конструктор
        public Transform(IRand algorithm) 
        { 
            // сохранить переданные параметры
            this.algorithm = RefObject.addRef(algorithm); 
        } 
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException 
        { 
            // освободить выделенные ресурсы
            RefObject.release(algorithm); super.onClose();
        }
        @Override public int update(byte[] data, 
            int dataOff, int dataLen, byte[] buf, int bufOff) throws IOException
        {
            byte[] next = new byte[1]; 
            
            // скопировать данные
            System.arraycopy(data, dataOff, buf, bufOff, dataLen);
            
            // выполнить преобразование
            for (int i = 0; i < dataLen; i++)
            {
                // сложить последовательности
                algorithm.generate(next, 0, 1); buf[bufOff + i] ^= next[0];  
            }
            return dataLen; 
        }
        @Override public int finish(byte[] data, 
            int dataOff, int dataLen, byte[] buf, int bufOff) throws IOException
        {
            // выполнить преобразование
            return update(data, dataOff, dataLen, buf, bufOff); 
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Фрагмент последовательности
    ///////////////////////////////////////////////////////////////////////////
    public static class Fragment
    {
        // конструктор
        public Fragment(int offset, byte[] value)
        {
            // сохранить переданные параметры
            this.offset = offset; this.value = value; 
        }
        // смещение и фрагмент последовательности
        public final int offset; public final byte[] value;   
    }
    ///////////////////////////////////////////////////////////////////////////
    // Тест известного ответа для поточных алгоритмов
    ///////////////////////////////////////////////////////////////////////////
    public static void knownTest(Cipher cipher, 
        byte[] keyValue, Fragment... fragments) throws Exception
    {
        // указать зашифровываемое значение
        byte[] src = new byte[] { 0x00 }; byte[] dest = new byte[1]; 
        
        // указать используемый ключ
        try (ISecretKey key = cipher.keyFactory().create(keyValue))
        {
            // вывести сообщение
            Test.dump("Key", key.value());
            
            // создать алгоритм зашифрования
            try (aladdin.capi.Transform transform = cipher.createEncryption(key, PaddingMode.NONE)) 
            { 
                // для всех фрагментов
                transform.init(); for (int offset = 0, i = 0; i < fragments.length; i++)
                {
                    // для всех байтов до фрагмента
                    for (; offset < fragments[i].offset; offset++) 
                    {
                        // выполнить преобразование
                        transform.update(src, 0, 1, dest, 0);
                    }
                    // для всех байтов фрагмента
                    for (; offset < fragments[i].offset + fragments[i].value.length; offset++)
                    {
                        // указать проверяемое значение
                        byte check = fragments[i].value[offset - fragments[i].offset]; 

                        // выполнить преобразование
                        transform.update(src, 0, 1, dest, 0);

                        // вывести сообщение
                        Test.println( 
                            "Offset = %1$d, Required = %2$02X, Result = %3$02X", 
                            offset, check, dest[0]
                        ); 
                        // сравнить значение
                        if (dest[0] != check) throw new IllegalArgumentException(); 
                    }
                }
            }
        }
        // вывести сообщение
        Test.println("OK"); Test.println();
    }
}

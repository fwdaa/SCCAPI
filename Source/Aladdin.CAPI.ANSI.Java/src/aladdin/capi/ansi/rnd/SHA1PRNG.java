package aladdin.capi.ansi.rnd;
import aladdin.*; 
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Генератор случайных данных SHA1PRNG
///////////////////////////////////////////////////////////////////////////////
public class SHA1PRNG extends RefObject implements IRand
{
    // алгоритм хэширования и начальное состояние
    private final Hash digest; private final byte[] state; 
    
    // невозвращенные данные хэширования 
    private final byte[] remainder; private int remCount;
    
    // конструктор
    public static SHA1PRNG getInstance(Object window, IRand rand) throws IOException
    {
        // создать алгоритм хэширования
        try (Hash digest = new aladdin.capi.ansi.hash.SHA1())
        {
            // выделить буфер для случайных данных
            byte[] seed = new byte[digest.hashSize()]; 
            
            // сгенерировать случайные данные
            rand.generate(seed, 0, seed.length);
        
            // создать генератор случайных данных
            return new SHA1PRNG(window, digest, seed); 
        }
    }
    // конструктор
    public static SHA1PRNG getInstance(Object window, byte[] seed) throws IOException
    {
        // создать алгоритм хэширования
        try (Hash digest = new aladdin.capi.ansi.hash.SHA1())
        {
            // создать генератор случайных данных
            return new SHA1PRNG(window, digest, seed); 
        }
    }
    // конструктор
    public SHA1PRNG(Object window, Hash digest, byte[] seed) throws IOException
    {
        // сохранить алгоритм хэширования
        this.digest = RefObject.addRef(digest); this.window = window; 
        
        // захэшировать начальные данные 
        digest.init(); digest.update(seed, 0, seed.length); 
        
        // вычислить хэш-значение от начальных данных
        state = new byte[digest.hashSize()]; digest.finish(state, 0); 

        // указать отсутствие данных 
        remainder = new byte[digest.hashSize()]; remCount = 0; digest.init(); 
    }
    // деструктор
    @Override protected void onClose() throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(digest); super.onClose();
    }
    // сгенерировать данные 
    @Override public void generate(byte[] buf, int bufOff, int bufLen) throws IOException
    {
        // при наличии данных 
        int copied = 0; if (remCount > 0)
        {
            // определить число байтов из последнего хэширования 
            copied = (bufLen < remainder.length - remCount) ? 
                bufLen : (remainder.length - remCount);
      
            // для всех байтов
            for (int m = 0; m < copied; m++)
            {
                // скопировать байты
                buf[bufOff + m] = remainder[remCount]; 
                
                // обнулить использованный байт
                remainder[remCount++] = 0;
            }
        }
        // пока не сгенерированы все данные 
        for (boolean modified = false; copied < bufLen; modified = false)
        {
            // захэшировать состояние
            digest.update(state, 0, state.length);
        
            // вычислить хэш-значение
            digest.finish(remainder, 0); digest.init(); 
        
            // для всех разрядов
            for (int n = 0, carry = 1; n < state.length; n++)
            {
                // сложить разряд
                int j = state[n] + remainder[n] + carry;

                // проверить изменение состояния 
                if (state[n] != (byte)j) modified = true;

                // сохранить значение и бит переноса
                state[n] = (byte)j; carry = j >> 8;
            }
            // явно изменить состояние
            if (!modified) state[0]++;
        
            // определить число байтов
            remCount = (bufLen - copied > remainder.length) ? 
                remainder.length : (bufLen - copied);
        
            // для всех байтов 
            for (int m = 0; m < remCount; m++)
            {
                // скопировать байты
                buf[bufOff + copied++] = remainder[m]; remainder[m] = 0;
            }
        }
        remCount %= remainder.length;
    } 
    // объект окна
    public @Override Object window() { return window; } private final Object window; 
}

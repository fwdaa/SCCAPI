package aladdin.capi.ansi.rnd;
import aladdin.*; 
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Генератор случайных данных SHA1PRNG
///////////////////////////////////////////////////////////////////////////////
public class SHA1PRNG extends RefObject implements IRand
{
    private final Hash digest; private final byte[] state; 
    
    private final byte[] remainder; private int remCount;
  
    // конструктор
    public SHA1PRNG(byte[] seed) throws IOException
    {
        digest = new aladdin.capi.ansi.hash.SHA1(); 
        
        digest.init(); digest.update(seed, 0, seed.length);
        
        state = new byte[20]; digest.finish(state, 0); 

        digest.init(); remainder = new byte[20]; remCount = 0; 
    }
    // деструктор
    @Override protected void onClose() throws IOException
    {
        // освободить выделенные ресурсы
        digest.close(); super.onClose();
    }
    // сгенерировать данные 
    @Override public void generate(byte[] buf, int bufOff, int bufLen) throws IOException
    {
        int i = 0; if (remCount > 0)
        {
            // определить число байтов из последнего хэширования 
            i = (bufLen < 20 - remCount) ? bufLen : (20 - remCount);
      
            // для всех байтов
            for (int m = 0; m < i; m++)
            {
                // скопировать байты
                buf[bufOff + m] = remainder[remCount]; 
                
                // обнулить использованный байт
                remainder[remCount++] = 0;
            }
        }
        // пока не сгенерированы все данные 
        for (boolean modified = false; i < bufLen; modified = false)
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
            remCount = (bufLen - i > 20) ? 20 : (bufLen - i);
        
            // для всех байтов 
            for (int m = 0; m < remCount; m++)
            {
                // скопировать байты
                buf[bufOff + i++] = remainder[m]; remainder[m] = 0;
            }
        }
        remCount %= 20;
    } 
    // объект окна
    public @Override Object window() { return null; }      
}

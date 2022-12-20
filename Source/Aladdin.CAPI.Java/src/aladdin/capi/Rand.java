package aladdin.capi;
import aladdin.*; 
import java.io.*;
import java.security.*; 

///////////////////////////////////////////////////////////////////////////
// Генератор случайных данных
///////////////////////////////////////////////////////////////////////////
public class Rand extends RefObject implements IRand
{
    // генератор случайных чисел
	private final java.util.Random generator; 
    
    // описатель окна и дополнительный генератор
    private final Object window; private final IRand rand; 

    // изменить окно для генератора
    public static IRand rebind(IRand rand, Object window) 
    {
        // вернуть генератор случайных данных
        return new Rand(rand, window);  
    }
	// конструктор
	private Rand(IRand rand, Object window) { this.generator = null; 

        // сохранить дополнительный генератор
        this.window = window; this.rand = RefObject.addRef(rand); 
    }
	// конструктор
	public Rand(Object window) { this(new SecureRandom(), window); }
    
    // конструктор
	public Rand(java.util.Random generator, Object window) 
    { 
        // сохранить переданные параметры
        super(); this.generator = generator; 
        
        // сохранить переданные параметры
        this.window = window; this.rand = null; 
    }
    // конструктор
	public Rand(java.util.Random generator, IRand rand) 
    { 
        // сохранить переданные параметры
        super(); this.generator = generator; 
        
        // сохранить генератор случайных данных
        this.rand = RefObject.addRef(rand); 
            
        // указать используемое окно
        this.window = (rand != null) ? rand.window() : null; 
    }
    // деструктор
    @Override protected void onClose() throws IOException 
    { 
        // освободить выделенные ресурсы
        RefObject.release(rand); super.onClose(); 
    }
    // создать генератор случайных данных
    @Override public IRand createRand(Object window) 
    {
        // вернуть генератор случайных данных
        return Rand.rebind(this, window);  
    }
    // сгенерировать случайные данные
	@Override public void generate(byte[] data, int dataOff, int dataLen) throws IOException
	{
		// сгенерировать случайные данные
		byte[] buffer = generate(dataLen); 

		// скопировать сгенерированные данные
		System.arraycopy(buffer, 0, data, dataOff, dataLen); 
	}
    // сгенерировать случайные данные
	public byte[] generate(int dataLen) throws IOException
	{
        // выделить буфер для данных
        byte[] buffer = new byte[dataLen]; 
            
		// сгенерировать случайные данные
         if (generator != null) generator.nextBytes(buffer); 

        // выделить дополнительный буфер данных
        if (rand != null) { byte[] buffer2 = new byte[dataLen];

            // сгенерировать дополнительные данные
            rand.generate(buffer2, 0, dataLen); 

            // выполнить сложение данных
            for (int i = 0; i < dataLen; i++) buffer[i] ^= buffer2[i]; 
        }
        return buffer; 
	}
    // описатель окна
    @Override public Object window() { return window; }
    
	///////////////////////////////////////////////////////////////////////
	// проверить диапазон для псевдослучайных данных
	///////////////////////////////////////////////////////////////////////
	public static boolean checkRange(
        byte[] data,        // 32-байтовая последовательность
	    int ones_min,	    // минимальное число единиц                           (   включительно)
	    int ones_max,	    // максимальное число единиц                          (не включительно)
		int changes_min,	// минимальное число изменений битов                  (   включительно)
		int changes_max,	// максимальное число изменений битов                 (не включительно)
		int max_seq_min,	// минимальная последовательность неизменяемых битов  (   включительно)
		int max_seq_max	    // максимальная последовательность неизменяемых битов (не включительно)
	 ) { 
        // создать массив для битов 
        byte[] bits = new byte[data.length * 8]; int ones = 0; 

	    // для всех байтов
	    for (int i = 0, index = 0; i < data.length; i++)
	    {
	        // для всех битов байта
	        for (int mask = 0x80; mask != 0; index++, mask >>= 1)
	        {
		        // извлечь требуемый бит
		        bits[index] = (byte)(((data[i] & mask) != 0) ? 1 : 0);

		        // увеличить число единиц
		        if (bits[index] != 0) ones++; 
	        }
	    }
	    // проверить число единиц
	    if (ones < ones_min || ones >= ones_max) return false; int changes = 0;

	    // указать начальные условия
	    int max_zeroes_seq = 0; int zeroes_seq = 0;
	    int max_ones_seq   = 0; int ones_seq   = 0;

	    // для всех битов
	    for (int i = 0; i < bits.length; i++)
	    {
		    // увеличить число изменений 
		    if (i != 0 && bits[i] != bits[i - 1]) 
		    {
                // проверить на максимальное число
			    if (++changes >= changes_max) return false; 
		    }
		    // при наличии нуля
		    if (bits[i] == 0) 
		    { 
			    // сохранить размер серии единиц
			    if (ones_seq > max_ones_seq) max_ones_seq = ones_seq;  
			
			    // сбросить серию единиц и продолжить серию нулей
			    ones_seq = 0; zeroes_seq++; 

			    // проверить на максимальное число
			    if (zeroes_seq >= max_seq_max) return false; 
		    }
		    else { 
			    // сохранить размер серии нулей
			    if (zeroes_seq > max_zeroes_seq) max_zeroes_seq = zeroes_seq;  

			    // сбросить серию нулей и продолжить серию единиц
			    zeroes_seq = 0; ones_seq++; 

			    // проверить на максимальное число
			    if (ones_seq >= max_seq_max) return false; 
		    }
	    }
	    // учесть размер последней серии
	    if (zeroes_seq > max_zeroes_seq) { max_zeroes_seq = zeroes_seq; }
	    if (ones_seq   > max_ones_seq  ) { max_ones_seq   = ones_seq  ; }

	    // проверить минимальное значение
	    if (changes < changes_min) return false; 
		
	    // проверить минимальные значения
	    return (max_zeroes_seq >= max_seq_min && max_ones_seq >= max_seq_min); 
    }
}

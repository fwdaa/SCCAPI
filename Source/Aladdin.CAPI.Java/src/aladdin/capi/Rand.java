package aladdin.capi;
import aladdin.*; 
import java.io.*;
import java.security.*; 
import java.lang.reflect.*; 

///////////////////////////////////////////////////////////////////////////
// Генератор случайных данных
///////////////////////////////////////////////////////////////////////////
public class Rand extends RefObject implements IRand
{
    // генератор случайных чисел
	private final java.util.Random generator; 
    
    // описатель окна и дополнительный генератор
    private final Object window; private final IRand rand; 

    // создать генератор на основе другого генератора
    @SuppressWarnings({"rawtypes"}) 
    public static IRand create(IRand rand, Class<? extends IRand> type) throws Throwable
    {
        // получить описание конструктора
        Constructor constructor = type.getConstructor(IRand.class); 

        // создать генератор на основе другого генератора
        try { return (IRand)constructor.newInstance(rand);  }

        // обработать возможное исключение
        catch (InvocationTargetException e) { throw e.getCause(); }
    }
    // изменить окно для генератора
    public static IRand rebind(IRand rand, Object window) 
    { 
        // изменить окно для генератора
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
        
        // сохранить дополнительный генератор
        this.window = rand.window(); this.rand = RefObject.addRef(rand); 
    }
    // деструктор
    @Override protected void onClose() throws IOException 
    { 
        // освободить выделенные ресурсы
        RefObject.release(rand); super.onClose(); 
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
}

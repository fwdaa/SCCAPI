package aladdin.capi.jcp;
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Генератор случайных чисел
///////////////////////////////////////////////////////////////////////////////
public final class SecureRandomSpi extends java.security.SecureRandomSpi
{
    // номер версии при сериализации
    private static final long serialVersionUID = 9086654708472650368L;
    
    // конструктор
    public SecureRandomSpi(Provider provider) 
     
        // сохранить переданные параметры
        { this.provider = provider; } private final Provider provider;
    
	@Override protected final void engineSetSeed(byte[] seed) {}

	@Override protected final byte[] engineGenerateSeed(int numBytes) 
	{
		// выделить буфер требуемого размера
		byte[] bytes = new byte[numBytes];  
		
		// сгенерировать случайные данные
		engineNextBytes(bytes); return bytes;  
	}
	@Override protected final void engineNextBytes(byte[] bytes) 
	{
        // получить генератор случайных данных
        try (IRand rand = provider.createRand(null))
        {
            // сгенерировать случайные данные
            rand.generate(bytes, 0, bytes.length);  
        }
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
	}
}

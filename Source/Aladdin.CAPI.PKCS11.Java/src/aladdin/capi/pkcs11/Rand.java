package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Генерация случайных данных PKCS11
///////////////////////////////////////////////////////////////////////////////
public class Rand extends RefObject implements IRand
{
	// используемый сеанс и описатель окна
	private final Session session; private final Object window; 	

	public Rand(Applet applet, byte[] seed, Object window) throws IOException
	{ 
		// открыть сеанс с токеном
		session = applet.openSession(API.CKS_RO_PUBLIC_SESSION); 
		try { 
            // установить стартовое значение генератора
            if (seed != null) session.seedRandom(seed, 0, seed.length);  
        }
        // обработать возможное исключение
        catch (Throwable e) { session.close(); throw e; } this.window = window; 
	}
	// деструктор
	@Override protected void onClose() throws IOException   
    { 
        // закрыть сеанс
        session.close(); super.onClose();
    } 
	// сгенерировать случайные данные
	@Override
	public void generate(byte[] bytes, int start, int len) throws IOException
	{
		// сгенерировать случайные данные
		session.generateRandom(bytes, start, len); 
	}
	// сгенерировать случайные данные
	public byte[] generate(int len) throws IOException
    {
        // выделить буфер требуемого размера
        byte[] buffer = new byte[len]; 

        // сгенерировать случайные данные
        generate(buffer, 0, len); return buffer; 
    }
    // обьект окна, связанного с генератором
	@Override public Object window() { return window; } 
};

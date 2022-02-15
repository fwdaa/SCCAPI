package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования PKCS11
///////////////////////////////////////////////////////////////////////////////
public abstract class Hash extends aladdin.capi.Hash
{
	// используемое устройство и используемый сеанс
	private final Applet applet; private Session session; private int total; 

	// конструктор
	protected Hash(Applet applet)
	{ 
		// сохранить переданные параметры
		this.applet = RefObject.addRef(applet); session = null; 
	}
	// деструктор
    @Override protected void onClose() throws IOException   
    { 
		// закрыть сеанс
		if (session != null) session.close(); 
        
        // освободить выделенные ресурсы
        RefObject.release(applet); super.onClose();
	}
	// используемое устройство 
	protected final Applet applet() { return applet; } 
    
	// параметры алгоритма
	protected abstract Mechanism getParameters(Session sesssion);
    
    // общий размер данных
    protected final int total() { return total; }
    
	// инициализировать алгоритм
    @Override
	public void init() throws IOException
    {
        // открыть новый сеанс 
        session = applet.openSession(API.CKS_RO_PUBLIC_SESSION); 
        try { 
            // получить параметры алгоритма
            Mechanism parameters = getParameters(session);
            
            // инициализировать алгоритм
            session.digestInit(parameters); total = 0; 
        }
        // обработать возможную ошибку
        catch (Throwable e) { session.close(); session = null; throw e; }
    }
	// захэшировать данные
    @Override
	public void update(byte[] data, int dataOff, int dataLen) throws IOException
    {
        // захэшировать данные
        if (dataLen > 0) session.digestUpdate(data, dataOff, dataLen); 
        
        // увеличить общий размер
        total += dataLen; 
    }
	// завершить хэширование данных
    @Override
	public int finish(byte[] buf, int bufOff) throws IOException
    {
        // завершить хэширование данных
        int bufLen = session.digestFinal(buf, bufOff);

        // проверить указание буфера
        if (buf == null) return bufLen; 
        
        // закрыть сеанс
        session.close(); session = null; return bufLen; 
    }
};

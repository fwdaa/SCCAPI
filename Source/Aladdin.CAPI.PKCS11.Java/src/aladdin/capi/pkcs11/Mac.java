package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.pkcs11.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки PKCS11
///////////////////////////////////////////////////////////////////////////////
public abstract class Mac extends aladdin.capi.Mac
{
	// используемое устройство и используемый сеанс
	private final Applet applet; private Session session; private int total; 

	// конструктор
	protected Mac(Applet applet)
	{ 
		// сохранить переданные параметры
		this.applet = RefObject.addRef(applet); session = null;
	}
	// деструктор
    @Override protected void onClose() throws IOException   
    { 
		// закрыть сеанс и освободить параметры
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
    
    // атрибуты ключа
    protected Attribute[] getKeyAttributes(int keySize)
    {
        // атрибуты ключа
        return applet.provider().secretKeyAttributes(keyFactory(), keySize, true); 
    }
	// инициализировать алгоритм
    @Override
	public void init(ISecretKey key) throws IOException, InvalidKeyException
    {
        // указать дополнительный атрибут ключа
        Attribute[] keyAttributes = new Attribute[] {
            new Attribute(API.CKA_SIGN, API.CK_TRUE)
        }; 
        // получить атрибуты ключа
        keyAttributes = Attribute.join(keyAttributes, getKeyAttributes(key.length()));  
        
        // открыть сеанс
        session = applet.openSession(API.CKS_RO_PUBLIC_SESSION); 
        try {
            // получить параметры алгоритма
            Mechanism parameters = getParameters(session); 
            
            // преобразовать тип ключа
            SessionObject sessionKey = applet.provider().toSessionObject(
                session, key, keyAttributes
            ); 
            // инициализировать алгоритм
            session.signInit(parameters, sessionKey.handle()); total = 0; 
        }
        // обработать возможную ошибку
        catch (Throwable e) { session.close(); session = null; throw e; }
    }
	// захэшировать данные
    @Override
	public void update(byte[] data, int dataOff, int dataLen) throws IOException
    {
        // захэшировать данные
        if (dataLen > 0) session.signUpdate(data, dataOff, dataLen); 
        
        // увеличить общий размер
        total += dataLen; 
    }
	// завершить выработку имитовставки
    @Override
	public int finish(byte[] buf, int bufOff) throws IOException 
    {
        // завершить выработку имитовставки
        int bufLen = session.signFinal(buf, bufOff);

        // проверить указание буфера
        if (buf == null) return bufLen; 

        // закрыть сеанс
        session.close(); session = null; return bufLen; 
    }
};

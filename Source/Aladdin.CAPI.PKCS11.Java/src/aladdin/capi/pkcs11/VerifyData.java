package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.pkcs11.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм проверки подписи данных
///////////////////////////////////////////////////////////////////////////
public abstract class VerifyData extends aladdin.capi.VerifyData
{
	// используемое устройство и используемый сеанс
	private final Applet applet; private Session session; 

	// конструктор
	public VerifyData(Applet applet)
	{
		// сохранить переданные параметры
		this.applet = RefObject.addRef(applet); session = null;
	}
	// деструктор
    @Override protected void onClose() throws IOException  
	{ 
		// закрыть сеанс
		if (session != null) session.close(); 
        
        // освободить выделнные ресурсы
        RefObject.release(applet); super.onClose();
	}
	// используемое устройство 
	protected final Applet applet() { return applet; } 

	// параметры алгоритма
	protected abstract Mechanism getParameters(
        Session sesssion, IParameters parameters
    ); 
	// инициализировать алгоритм
    @Override
	public void init(IPublicKey publicKey, byte[] signature) 
        throws SignatureException, IOException
    {
        // вызвать базовую функцию
        super.init(publicKey, signature);
        
        // указать дополнительные атрибуты ключа
        Attribute[] keyAttributes = new Attribute[] {
            new Attribute(API.CKA_VERIFY, API.CK_TRUE)
        }; 
    	// при необходимости закрыть старый сеанс
		if (session != null) { session.close(); session = null; } 
        
        // сохранить переданные параметры
        session = applet.openSession(API.CKS_RO_PUBLIC_SESSION); 
        try { 
            // получить параметры алгоритма
            Mechanism parameters = getParameters(session, publicKey.parameters()); 
            
            // получить информацию об алгоритме
            MechanismInfo info = applet.getAlgorithmInfo(parameters.id()); 
            
            // преобразовать тип ключа
            SessionObject sessionKey = applet.provider().toSessionObject(
                session, publicKey, info, keyAttributes
            ); 
            // инициализировать алгоритм
            session.verifyInit(parameters, sessionKey.handle());
        }
        // обработать возможную ошибку
        catch (Throwable e) { session.close(); session = null; throw e; }
    }
	// обработать данные
    @Override
	public void update(byte[] data, int dataOff, int dataLen) throws IOException
    {
        // захэшировать данные
        if (dataLen > 0) session.verifyUpdate(data, dataOff, dataLen); 
    }
	// проверить подпись данных
    @Override public void finish() throws IOException
    {
        // проверить подпись
        try { session.verifyFinal(signature()); }
        finally { 
            // закрыть сеанс
            session.close(); session = null; 
        } 
    }
};

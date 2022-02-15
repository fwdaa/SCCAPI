package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.pkcs11.*;
import java.io.*; 
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм выработки подписи данных
///////////////////////////////////////////////////////////////////////////
public abstract class SignData extends aladdin.capi.SignData
{
	// используемое устройство и используемый сеанс 
	private final Applet applet; private Session session;

	// конструктор
	public SignData(Applet applet)
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
	protected abstract Mechanism getParameters(
        Session sesssion, IParameters parameters
    ); 
	// инициализировать алгоритм
    @Override
	public void init(IPrivateKey privateKey, IRand rand) throws IOException
    {
        // вызвать базовую функцию
        super.init(privateKey, rand); 
                
        // указать дополнительные атрибуты ключа
        Attribute[] keyAttributes = new Attribute[] {
            new Attribute(API.CKA_SIGN,  API.CK_TRUE)
        }; 
        // открыть сеанс
        session = applet.openSession(API.CKS_RO_USER_FUNCTIONS); 
        try { 
            // получить параметры алгоритма
            Mechanism parameters = getParameters(session, privateKey.parameters()); 
            
            // получить информацию об алгоритме
            MechanismInfo info = applet.getAlgorithmInfo(parameters.id()); 
            
            // преобразовать тип ключа
            SessionObject sessionKey = applet.provider().toSessionObject(
                session, privateKey, info, keyAttributes
            ); 
            // инициализировать алгоритм
            session.signInit(parameters, sessionKey.handle());
        }
        // обработать возможную ошибку
        catch (Throwable e) { session.close(); session = null; throw e; }
    }
	// обработать данные
    @Override
	public void update(byte[] data, int dataOff, int dataLen) throws IOException
    {
        // захэшировать данные
        if (dataLen > 0) session.signUpdate(data, dataOff, dataLen); 
    }
	// получить подпись данных
    @Override
	public byte[] finish(IRand rand) throws IOException
    {
        // выделить память для подписи
        byte[] signature = new byte[session.signFinal(null, 0)]; 

        // получить подпись
        signature = Arrays.copyOf(signature, session.signFinal(signature, 0));

        // закрыть сеанс
        session.close(); session = null; super.finish(rand); return signature;
    }
};

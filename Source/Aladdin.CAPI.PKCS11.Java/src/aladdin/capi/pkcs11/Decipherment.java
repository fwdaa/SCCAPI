package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////
// Ассиметричный алгоритм шифрования
///////////////////////////////////////////////////////////////////////
public abstract class Decipherment extends aladdin.capi.Decipherment
{
    // физическое устройство
    private final Applet applet;		
    
	// конструктор
	protected Decipherment(Applet applet) 
	{ 	
		// сохранить переданные параметры
		this.applet = RefObject.addRef(applet); 
    } 
	// деструктор
    @Override protected void onClose() throws IOException   
    { 
        // освободить выделенные ресурсы
        RefObject.release(applet); super.onClose();
    } 
	// используемое устройство 
	protected final Applet applet() { return applet; } 

	// параметры алгоритма
	protected abstract Mechanism getParameters(Session sesssion, IParameters parameters);  

	// расшифровать данные
    @Override
	public byte[] decrypt(IPrivateKey privateKey, byte[] data) throws IOException
    {
        // указать дополнительные атрибуты ключа
        Attribute[] keyAttributes = new Attribute[] {
            new Attribute(API.CKA_DECRYPT, API.CK_TRUE)
        }; 
        // открыть сеанс и раскодировать данные
        try (Session session = applet.openSession(API.CKS_RO_USER_FUNCTIONS)) 
        {
            // получить параметры алгоритма
            Mechanism parameters = getParameters(session, privateKey.parameters()); 
            
            // получить информацию об алгоритме
            MechanismInfo info = applet.getAlgorithmInfo(parameters.id()); 
            
            // преобразовать тип ключа
            SessionObject sessionKey = applet.provider().toSessionObject(
                session, privateKey, info, keyAttributes
            );
            // инициализировать алгоритм
            session.decryptInit(parameters, sessionKey.handle());

            // расшифровать данные
            return session.decrypt(data, 0, data.length);
        }
    }
}

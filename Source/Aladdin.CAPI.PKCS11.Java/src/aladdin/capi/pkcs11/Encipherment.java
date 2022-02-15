package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.pkcs11.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////
// Ассиметричный алгоритм шифрования
///////////////////////////////////////////////////////////////////////
public abstract class Encipherment extends aladdin.capi.Encipherment
{
    // физическое устройство
    private final Applet applet;
    
	// конструктор
	protected Encipherment(Applet applet) 
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
	protected abstract Mechanism getParameters(Session session, IParameters parameters); 
    
	// зашифровать данные
    @Override
	public byte[] encrypt(IPublicKey publicKey, IRand rand, byte[] data) throws IOException
    {
        // указать дополнительные атрибуты ключа
        Attribute[] keyAttributes = new Attribute[] {
            new Attribute(API.CKA_ENCRYPT, API.CK_TRUE)
        }; 
        // открыть сеанс
        try (Session session = applet.openSession(API.CKS_RO_PUBLIC_SESSION))
        {
            // получить параметры алгоритма
            Mechanism parameters = getParameters(session, publicKey.parameters()); 
            
            // получить информацию об алгоритме
            MechanismInfo info = applet.getAlgorithmInfo(parameters.id()); 
            
            // преобразовать тип ключа
            SessionObject sessionKey = applet.provider().toSessionObject(
                session, publicKey, info, keyAttributes
            );
            // инициализировать алгоритм
            session.encryptInit(parameters, sessionKey.handle());

            // зашифровать данные
            return session.encrypt(data, 0, data.length);
        }
    }
};

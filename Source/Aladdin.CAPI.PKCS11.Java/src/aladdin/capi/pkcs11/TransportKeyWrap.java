package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.asn1.iso.*; 
import aladdin.capi.*; 
import aladdin.pkcs11.*;
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм обмена ключа PKCS11
///////////////////////////////////////////////////////////////////////////////
public abstract class TransportKeyWrap extends aladdin.capi.TransportKeyWrap
{
    // физическое устройство
    private final Applet applet;
    
	// конструктор
	protected TransportKeyWrap(Applet applet) 
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

	// действия стороны-отправителя
    @Override
	public TransportKeyData wrap(AlgorithmIdentifier algorithmParameters, 
        IPublicKey publicKey, IRand rand, ISecretKey CEK) 
        throws IOException, InvalidKeyException
    {
        // указать дополнительные атрибуты ключа
        Attribute[] keyAttributes = new Attribute[] {
            new Attribute(API.CKA_WRAP , API.CK_TRUE)
        }; 
        // указать атрибуты защищаемого ключа
        Attribute[] attributes = applet.provider().secretKeyAttributes(
            CEK.keyFactory(), CEK.length(), true
        ); 
        // открыть сеанс /* TODO */
        try (Session session = applet.openSession(API.CKS_RW_USER_FUNCTIONS))
        {
            // получить параметры алгоритма
            Mechanism parameters = getParameters(session, publicKey.parameters(), rand); 
            
            // получить информацию об алгоритме
            MechanismInfo info = applet.getAlgorithmInfo(parameters.id()); 
            
            // преобразовать тип ключа
            SessionObject sessionPublicKey = applet.provider().toSessionObject(
                session, publicKey, info, keyAttributes
            ); 
            // преобразовать тип ключа
            SessionObject sessionKey = applet.provider().toSessionObject(
                session, CEK, attributes
            ); 
            // зашифровать ключ
            byte[] data = session.wrapKey(
                parameters, sessionPublicKey.handle(), sessionKey.handle()
            );
            // вернуть зашифрованный ключ с параметрами обмена
            return new TransportKeyData(algorithmParameters, data);
        }
    }
	// параметры алгоритма
	protected abstract Mechanism getParameters(
		Session sesssion, IParameters parameters, IRand rand) throws IOException; 
};

package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*;
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Ключ PKCS11
///////////////////////////////////////////////////////////////////////////////
public class SecretKey extends RefObject implements ISecretKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = 9129970231075157145L;

    // смарт-карта и тип ключа
	private final Applet applet; private final SecretKeyFactory keyFactory; 
    // атрибуты ключа
    private final Attributes keyAttributes;
    
	// конструктор
	public SecretKey(Applet applet, SecretKeyFactory keyFactory, Attributes keyAttributes)
    { 
        // сохранить переданные параметры
        this.applet = RefObject.addRef(applet); 
        
        // сохранить атрибуты ключа
        this.keyFactory = keyFactory; this.keyAttributes = keyAttributes;
    }
    // деструктор
	@Override protected void onClose() throws IOException   
    { 
        // проверить необходимость удаления
        if (applet != null)
        try { 
            // создать сеанс
            try (Session session = applet.openSession(API.CKS_RW_USER_FUNCTIONS)) 
            { 
                // получить ссылку на объект
                SessionObject sessionObject = toSessionObject(session, null); 

                // удалить объект на токене
                session.destroyObject(sessionObject); 
            }
        }
        // освободить выделенные ресурсы
        catch (IOException e) {} RefObject.release(applet); super.onClose();
	}
    // тип ключа
	@Override public SecretKeyFactory keyFactory() { return keyFactory; }
	// размер ключа
	@Override public int length() { return value().length; }
    
    // значение ключа
    @Override public byte[] value() 
    {
		// получить требуемый атрибут
		Attribute attribute = keyAttributes.get(API.CKA_VALUE); 

        // вернуть значение атрибута
		return (attribute != null) ? (byte[])attribute.value() : null; 
    }
    // тип ключа 
    @Override public String getAlgorithm() { return keyFactory().names()[0]; }
    // формат закодированного представления
    @Override public String getFormat() { return "RAW"; }
    // закодированное представление
    @Override public byte[] getEncoded() { return value(); }
    
	// создать сеансовый объект
	public SessionObject toSessionObject(
        Session session, Attribute[] attributes) throws IOException
    {
        // получить значение атрибута
        Attribute tokenAttribute = keyAttributes.get(API.CKA_TOKEN); 
        
        // при отсутствии ключа на смарт-карте
        if (tokenAttribute == null || (Byte)tokenAttribute.value() == API.CK_FALSE)
        {
            // создать сеансовый объект
            return session.createObject(keyAttributes.join(attributes).toArray()); 
        }
        else {
            // выделить память для атрибутов поиска
            Attributes findAttributes = new Attributes(tokenAttribute, 

                // указать для поиска тип и идентификатор объекта
                keyAttributes.get(API.CKA_CLASS), keyAttributes.get(API.CKA_ID)
            );  
            // найти на смарт-карте ключ
            return session.findObject(findAttributes.join(attributes).toArray()); 
        }
    }
}

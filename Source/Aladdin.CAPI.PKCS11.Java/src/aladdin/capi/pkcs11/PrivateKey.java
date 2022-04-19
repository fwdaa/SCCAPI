package aladdin.capi.pkcs11;
import aladdin.capi.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Личный ключ PKCS11
///////////////////////////////////////////////////////////////////////////
public abstract class PrivateKey extends aladdin.capi.PrivateKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = 260539481459225260L;

    // конструктор 
	public PrivateKey(Provider provider, SecurityObject scope, String keyOID) 
	{ 
		// сохранить переданные параметры
		super(provider, scope, keyOID); 
    } 
	// создать сеансовый объект
	public SessionObject toSessionObject(
        Session session, Attribute[] attributes) throws IOException
    {
        // получить атрибуты ключа
        Attributes keyAttributes = keyAttributes(); 
        
        // получить значение атрибута
        Attribute tokenAttribute = keyAttributes.get(API.CKA_TOKEN); 
        
        // при отсутствии ключа на смарт-карте
        if (tokenAttribute == null || (Byte)tokenAttribute.value() == API.CK_FALSE)
        {
            // создать сеансовый объект
            return session.createObject(keyAttributes.join(attributes).toArray(), null); 
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
    // атрибуты ключа
    protected abstract Attributes keyAttributes(); 
}

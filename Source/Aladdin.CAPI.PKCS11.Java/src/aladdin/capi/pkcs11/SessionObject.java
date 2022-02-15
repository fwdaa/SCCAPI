package aladdin.capi.pkcs11;
import aladdin.pkcs11.*;
import aladdin.pkcs11.Exception; 
import aladdin.pkcs11.jni.*;
import aladdin.util.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////////
// Сеансовый объект PKCS11
///////////////////////////////////////////////////////////////////////////////
public class SessionObject
{
	private final Session	session;	// сеанс объекта
	private final long		hObject;	// описатель объекта

	// конструктор
	public SessionObject(Session session, long hObject)
	{
		this.session = session;				// сеанс объекта
		this.hObject = hObject;				// описатель объекта
	}
	public final Session session() { return session; }
	public final long	 handle	() { return hObject; }

	///////////////////////////////////////////////////////////////////////////
	// Создание копии объекта
	///////////////////////////////////////////////////////////////////////////
	public final SessionObject copy(Attribute[] attributes) throws Exception
	{
        // преобразовать атрибуты
        CK_ATTRIBUTE[] attrs = Attribute.convert(attributes); 
        
		// создать копию объекта
		long handle = session.module().copyObject(session.handle(), hObject, attrs);
        
		// вернуть созданный объект
		return new SessionObject(session, handle); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Получение атрибутов объекта PKCS11
	///////////////////////////////////////////////////////////////////////////
	public final Attribute[] getAttributes(Attribute[] attributes) throws Exception
	{
        // преобразовать атрибуты
        CK_ATTRIBUTE[] attrs = Attribute.convert(attributes); 
        
        // получить значения атрибутов
        attrs = session.module().getAttributes(session.handle(), hObject, attrs);
        
        // заполнить список атрибутов
        for (int i = 0; i < attributes.length; i++) 
        {
            // проверить наличие значения
            if (attrs[i].value == null) continue; 
            
            // указать значение атрибута
            attributes[i] = new Attribute(attrs[i].type, attrs[i].value); 
        }
        return attributes; 
	}
	public final Attribute getAttribute(Attribute attribute) throws Exception 
	{
		// получить атрибут объекта
		Attribute[] attributes = getAttributes(new Attribute[] {attribute}); 
        
        // вернуть полученный атрибут
        return attributes[0]; 
	}
	public final Attribute[] getSafeAttributes(Attribute[] attributes) 
	{
        // создать список атрибутов
        List<Attribute> attrs = new ArrayList<Attribute>(); 
        
        // для всех атрибутов
        for (Attribute attribute : attributes)
        {
            // получить атрибут объекта
            Attribute attr = getSafeAttribute(attribute); 
            
            // добавить атрибут в список
            if (attr != null) attrs.add(attr); 
        }
        // вернуть найденные атрибуты
        return attrs.toArray(new Attribute[attrs.size()]); 
	}
	public final Attribute getSafeAttribute(Attribute attribute) 
	{
        // получить значение атрибута
        try { return getAttribute(attribute); }
        
        // обработать возможную ошибку
        catch (Throwable e) { return null; }
	}
	public final void setAttributes(Attribute[] attributes) throws Exception
	{
        // преобразовать атрибуты
        CK_ATTRIBUTE[] attrs = Attribute.convert(attributes); 
        
		// установить атрибуты объекта
		session.module().setAttributes(session.handle(), hObject, attrs);
	}
	// размер объекта на смарт-карте
	public final long getObjectSize() throws Exception
	{
		// размер объекта на смарт-карте
		return session.module().getObjectSize(session.handle(), hObject); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Получение стандартных атрибутов объекта PKCS11
	///////////////////////////////////////////////////////////////////////////
    public boolean onToken()
	{
        try { 
            // получить требуемый атрибут
            Attribute attribute = getAttribute(new Attribute(API.CKA_TOKEN, API.CK_FALSE)
            ); 
            // извлечь атрибут объекта
            return (Byte)attribute.value() != API.CK_FALSE;
        }
        // обработать неожидаемое исключение
        catch (Exception e) { throw new RuntimeException(e); }
	}
	public final long getObjectClass() throws Exception 
	{ 
		// извлечь атрибут объекта
		Attribute attribute = getAttribute(new Attribute(API.CKA_CLASS, Long.class));
        
        // вернуть значение атрибута
        return (long)attribute.value(); 
	}
	public final long getKeyType() throws Exception 
	{ 
		// извлечь атрибут объекта
		Attribute attribute = getAttribute(new Attribute(API.CKA_KEY_TYPE, Long.class));
        
        // вернуть значение атрибута
        return (long)attribute.value(); 
	}
	public final byte[] getID() throws Exception  
	{ 
		// извлечь атрибут объекта
        Attribute attribute = getAttribute(new Attribute(API.CKA_ID, byte[].class)); 
        
        // вернуть значение атрибута
        return (byte[])attribute.value(); 
	}
	public String getLabel() throws IOException
	{ 
		// получить атрибут объекта
		Attribute attribute = getAttribute(new Attribute(API.CKA_LABEL, new byte[0])); 

		// проверить наличие атрибута
		if (((byte[])attribute.value()).length == 0) return Array.toHexString(getID()); 
        
        // раскодировать значение атрибута
        return new String((byte[])attribute.value(), "UTF-8");
	}
	public final byte[] getValue() throws Exception  
	{ 
		// извлечь атрибут объекта
        Attribute attribute = getAttribute(new Attribute(API.CKA_VALUE, byte[].class)); 
        
        // вернуть значение атрибута
        return (byte[])attribute.value(); 
	}
}; 

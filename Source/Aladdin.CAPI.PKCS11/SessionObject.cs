using System;
using System.Collections.Generic;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////////
    // Сеансовый объект PKCS11
    ///////////////////////////////////////////////////////////////////////////////
    public class SessionObject
    {
        // сеанс объекта и описатель объекта
	    private Session	session; private UInt64	hObject;	

	    // конструктор
	    public SessionObject(Session session, UInt64 hObject)
	    {
            // сохранить переданные параметры
		    this.session = session; this.hObject = hObject;
	    }
	    // используемый сеанс и описатель объекта			
	    public Session Session { get { return session; } }
	    public UInt64  Handle  { get { return hObject; } }

	    ///////////////////////////////////////////////////////////////////////////
	    // Создание копии объекта
	    ///////////////////////////////////////////////////////////////////////////
	    public SessionObject Сopy(Attribute[] attributes)
	    {
		    // создать копию объекта
		    UInt64 hObject = session.Module.CopyObject(
			    session.Handle, this.hObject, attributes
		    );
		    // вернуть созданны объект
		    return new SessionObject(session, hObject);
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Получение атрибутов объекта PKCS11
	    ///////////////////////////////////////////////////////////////////////////
	    public Attribute[] GetAttributes(Attribute[] attributes)
	    {
            // создать список атрибутов
            Aladdin.PKCS11.Attribute[] attrs = 
                new Aladdin.PKCS11.Attribute[attributes.Length]; 

            // скопировать атрибуты
            Array.Copy(attributes, 0, attrs, 0, attributes.Length); 

		    // получить атрибуты объекта
		    attrs = session.Module.GetAttributes(session.Handle, hObject, attrs); 

            // для всех атрибутов
            for (int i = 0; i < attributes.Length; i++)
            {
                // проверить наличие значения
                if (attrs[i].Value == null) continue; 
            
                // указать значение атрибута
                attributes[i] = new Attribute(attrs[i].Type, attrs[i].Value); 
            }
            return attributes; 
	    }
	    public Attribute GetAttribute(Attribute attribute)
	    {
		    // создать список типов атрибутов
		    Attribute[] attributes = new Attribute[] {attribute}; 

		    // получить атрибут объекта
		    return GetAttributes(attributes)[0];
	    }
	    public Attribute[] GetSafeAttributes(Attribute[] attributes) 
	    {
            // создать список атрибутов
            List<Attribute> attrs = new List<Attribute>(); 
        
            // для всех атрибутов
            foreach (Attribute attribute in attributes)
            {
                // получить атрибут объекта
                Attribute attr = GetSafeAttribute(attribute); 
            
                // добавить атрибут в список
                if (attr != null) attrs.Add(attr); 
            }
            // вернуть найденные атрибуты
            return attrs.ToArray(); 
	    }
	    public Attribute GetSafeAttribute(Attribute attribute)
	    {
            // получить значение атрибута
            try { return GetAttribute(attribute); } catch { return null; }
	    }
	    public void SetAttributes(Attribute[] attributes)
	    {
		    // установить атрибуты объекта
		    session.Module.SetAttributes(session.Handle, hObject, attributes);
	    }
	    // размер объекта на смарт-карте
	    public int GetObjectSize()
	    {
		    // размер объекта на смарт-карте
		    return session.Module.GetObjectSize(session.Handle, hObject); 
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Получение стандартных атрибутов объекта PKCS11
	    ///////////////////////////////////////////////////////////////////////////
	    public bool OnToken() 
	    {
		    // получить требуемый атрибут
		    Attribute attribute = GetAttribute(
                new Attribute(API.CKA_TOKEN, API.CK_FALSE)
            ); 
		    // извлечь атрибут объекта
		    return attribute.GetByte() != API.CK_FALSE;
	    }
	    public ulong GetClass()
        { 
		    // получить требуемый атрибут
		    Attribute attribute = GetAttribute(new Attribute(API.CKA_CLASS)); 

		    // извлечь атрибут объекта
            return attribute.GetLong(session.Module);
	    }
	    public ulong GetKeyType()
        { 
		    // получить требуемый атрибут
		    Attribute attribute = GetAttribute(new Attribute(API.CKA_KEY_TYPE)); 

		    // извлечь атрибут объекта
            return attribute.GetLong(session.Module);
	    }
	    public string GetLabel()
        { 
		    // получить атрибут объекта
		    Attribute attribute = GetAttribute(new Attribute(API.CKA_LABEL, new byte[0])); 

		    // при наличии строки раскодировать строку
		    if (attribute.Value.Length != 0) return attribute.GetString();

		    // получить идентификатор объекта
		    return Arrays.ToHexString(GetID()); 
	    }
        // извлечь атрибут объекта
	    public byte[] GetID   () { return GetAttribute(new Attribute(API.CKA_ID   )).Value; }
	    public byte[] GetValue() { return GetAttribute(new Attribute(API.CKA_VALUE)).Value; }
    }; 
}

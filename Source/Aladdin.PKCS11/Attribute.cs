using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Permissions;
using System.Runtime.InteropServices;

namespace Aladdin.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Информация об атрибуте
    ///////////////////////////////////////////////////////////////////////////
    public class Attribute
    {
	    // тип и значение атрибута
	    private UInt64 type; private byte[] value;

	    // конструктор
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public Attribute(API32.CK_ATTRIBUTE attribute) 
	    { 
		    // сохранить тип атрибута 
		    type = attribute.type; if (attribute.pValue == IntPtr.Zero) value = null; 
		    else {
			    // выделить память для значения атрибута
			    value = new byte[attribute.ulValueLen]; if (attribute.ulValueLen > 0) 

				    // скопировать значение атрибута
				    Marshal.Copy(attribute.pValue, value, 0, attribute.ulValueLen); 
		    }
	    }
	    // конструктор
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
	    public Attribute(API64.CK_ATTRIBUTE attribute) 
	    { 
		    // сохранить тип атрибута 
		    type = attribute.type; if (attribute.pValue == IntPtr.Zero) value = null; 
		    else {
			    // выделить память для значения атрибута
			    value = new byte[(int)attribute.ulValueLen]; if (attribute.ulValueLen > 0) 

				    // скопировать значение атрибута
				    Marshal.Copy(attribute.pValue, value, 0, (int)attribute.ulValueLen); 
		    }
	    }
	    // конструктор
	    public Attribute(UInt64 type) { this.type = type; this.value = null; }
	    // конструктор
	    public Attribute(UInt64 type, byte[] value) 
	    { 
		    // сохранить тип и значение атрибута 
		    this.type = type; this.value = value; 
	    }
	    // закодировать данные
	    public Attribute(UInt64 type, byte value)
	    {
		    // закодировать данные
		    this.type = type; this.value = new byte[] { value }; 
	    }
	    // закодировать данные
	    public Attribute(UInt64 type, string value)
	    {
		    // закодировать данные
		    this.type = type; this.value = System.Text.Encoding.UTF8.GetBytes(value); 
	    }
	    // тип и значение атрибута
	    public UInt64 Type	{ get { return type;  }} 
	    public Byte[] Value { get { return value; }} 

	    // раскодированное значение атрибута
	    public Byte   GetByte  () { return value[0]; }
	    public String GetString() 
	    { 
		    // раскодировать значение атрибута
		    return System.Text.Encoding.UTF8.GetString(value); 
	    }
        public UInt64 GetLong(Module module)
        {
            // раскодировать значение атрибута
            return module.DecodeLong(value); 
        }
	    // объединить списки атрибутов
	    public static A[] Join<A>(A[] attributes1, A[] attributes2) where A : Attribute 
	    {
		    // проверить наличие атрибутов
		    if (attributes1 == null && attributes2 == null) return new A[0];
        
		    // проверить наличие атрибутов
		    if (attributes1 == null) return attributes2; 
		    if (attributes2 == null) return attributes1; 
        
            // создать список атрибутов
            List<A> attributes = new List<A>(); 
        
            // создать список типов атрибутов
            List<UInt64> attributeTypes = new List<UInt64>(); 
        
            // для всех атрибутов
            foreach (A attribute in attributes1)
            {
                // получить порядковый номер атрибута
                int index = attributeTypes.IndexOf(attribute.type); 
            
                // перезаписать атрибут
                if (index >= 0) attributes[index] = attribute; 
            
                // добавить атрибут
                else { attributes.Add(attribute); attributeTypes.Add(attribute.Type); }
            }
            // для всех атрибутов
            foreach (A attribute in attributes2)
            {
                // получить порядковый номер атрибута
                int index = attributeTypes.IndexOf(attribute.type); 
            
                // перезаписать атрибут
                if (index >= 0) attributes[index] = attribute; 
            
                // добавить атрибут
                else { attributes.Add(attribute); attributeTypes.Add(attribute.Type); }
            }
            // вернуть набор атрибутов
            return attributes.ToArray(); 
        }
    } 
}

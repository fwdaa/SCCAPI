package aladdin.capi.pkcs11;
import aladdin.pkcs11.jni.*;
import java.io.*; 
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Информация об атрибуте
///////////////////////////////////////////////////////////////////////////
public class Attribute
{
	// тип и значение атрибута
	private final long type; private Object value;
    
    // класс значения атрибута
    private final Class<?> valueClass; 

	// конструктор
	public Attribute(CK_ATTRIBUTE attribute) 
	{ 
		// сохранить тип и значение атрибута 
		this.type = attribute.type; value = attribute.value; 
        
        // получить класс значения
        this.valueClass = attribute.valueClass;
	}
	// конструктор
	public Attribute(long type, Class<?> valueClass) 
	{ 
		// сохранить тип и значение атрибута 
		this.type = type; value = null; 
        
        // получить класс значения
        this.valueClass = valueClass;
	}
	// конструктор
	public Attribute(long type, Object value) 
	{ 
		// сохранить тип и значение атрибута 
		this.type = type; this.value = value; 
        
        // получить класс значения
        this.valueClass = value.getClass();
	}
	public Attribute(long type, String value)
	{
		// сохранить тип и значение атрибута 
		try { this.type = type; this.value = value.getBytes("UTF-8"); 
        
            // получить класс значения
            this.valueClass = this.value.getClass();
        }
		// обработать возможную ошибку
		catch (UnsupportedEncodingException e) { throw new RuntimeException(e); }
	}
	// закодировать данные
	public Attribute(long type, byte value)
	{
		// сохранить тип и класс значения атрибута
		this.type = type; this.valueClass = Byte.class; this.value = value;
    }
	// закодировать данные
	public Attribute(long type, long value)
	{
		// выделить память для закодированных данных
		this.type = type; this.valueClass = Long.class; this.value = value;  
	}
	// тип и значение атрибута
	public final long 	type ()	{ return type;  }  
	public final Object value()	{ return value; } 
    
    // класс значения атрибута
    public final Class<?> valueClass() { return valueClass; } 
    
    // выполнить преобразование типа
    public final CK_ATTRIBUTE convert()
    {
        // выполнить преобразование типа
        if (value != null) return new CK_ATTRIBUTE(type, value); 
        
        // выполнить преобразование типа
        else return new CK_ATTRIBUTE(type, valueClass); 
    }
	// преобразовать тип атрибутов
	public static CK_ATTRIBUTE[] convert(Attribute[] attributes)
	{
        // проверить наличие атрибутов
        if (attributes == null) return new CK_ATTRIBUTE[0]; 
        
		// выделить требуемую память
		List<CK_ATTRIBUTE> list = new ArrayList<CK_ATTRIBUTE>(); 
		
		// для всех атрибутов
		for (Attribute attribute : attributes)
		{
            // выполнить преобразование типа
            list.add(attribute.convert()); 
		}
        // вернуть преобразованные атрибуты
		return list.toArray(new CK_ATTRIBUTE[list.size()]); 
	}
	// объединить списки атрибутов
	public static Attribute[] join(Attribute[] attributes1, Attribute[] attributes2)
	{
		// проверить наличие атрибутов
		if (attributes1 == null && attributes2 == null) return new Attribute[0];
        
		// проверить наличие атрибутов
		if (attributes1 == null) return attributes2; 
		if (attributes2 == null) return attributes1; 
        
        // создать список атрибутов
        List<Attribute> attributes = new ArrayList<Attribute>(); 
        
        // создать список типов атрибутов
        List<Long> attributeTypes = new ArrayList<Long>(); 
        
        // для всех атрибутов
        for (Attribute attribute : attributes1)
        {
            // получить порядковый номер атрибута
            int index = attributeTypes.indexOf(attribute.type); 
            
            // перезаписать атрибут
            if (index >= 0) attributes.set(index, attribute); 
            
            // добавить атрибут
            else { attributes.add(attribute); attributeTypes.add(attribute.type); }
        }
        // для всех атрибутов
        for (Attribute attribute : attributes2)
        {
            // получить порядковый номер атрибута
            int index = attributeTypes.indexOf(attribute.type); 
            
            // перезаписать атрибут
            if (index >= 0) attributes.set(index, attribute); 
            
            // добавить атрибут
            else { attributes.add(attribute); attributeTypes.add(attribute.type); }
        }
        // вернуть набор атрибутов
        return attributes.toArray(new Attribute[attributes.size()]); 
    }
}

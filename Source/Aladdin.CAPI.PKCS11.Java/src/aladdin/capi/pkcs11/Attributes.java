package aladdin.capi.pkcs11;
import java.util.*; 

///////////////////////////////////////////////////////////////////////////////
// Атрибуты ключа PKCS11
///////////////////////////////////////////////////////////////////////////////
public class Attributes 
{
    // атрибуты ключа
	private final Map<Long, Attribute> attributes; 

	// конструктор
	public Attributes(Attribute... attributes) 
	{
        // создать набор атрибутов
        this.attributes = new HashMap<Long, Attribute>(); 
        
		// проверить наличие атрибутов
		if (attributes == null || attributes.length == 0) return; 
        
        // для всех атрибутов
        for (Attribute attribute : attributes) 
        {
            // добавить атрибут в набор
            this.attributes.put(attribute.type(), attribute);
        }
	}
	// конструктор
	private Attributes(Map<Long, Attribute> attributes) 
    {
        // сохранить переданные параметры
        this.attributes = attributes; 
    }
    // набор атрибутов
    public final Attribute[] toArray() 
    { 
        // создать пустой список атрибутов
        Attribute[] attrs = new Attribute[attributes.size()]; 
        
        // заполнить набор атрибутов
        return attributes.values().toArray(attrs); 
    }
	// найти атрибут
	public final Attribute get(long type) 
	{
        // найти атрибут
		return attributes.get(type); 
	}
	// объединить списки атрибутов
	public final Attributes join(Attributes attributes)
    {
		// проверить наличие атрибутов
		if (attributes == null) return this; 
        
        // создать набор атрибутов
        Map<Long, Attribute> result = new HashMap<Long, Attribute>(this.attributes); 

        // для всех атрибутов
        for (Attribute attribute : attributes.attributes.values()) 
        {
            // добавить/заменить атрибут в набор
            result.put(attribute.type(), attribute);
        }
        // вернуть набор атрибутов
        return new Attributes(result); 
    }
	// объединить списки атрибутов
	public final Attributes join(Attribute... attributes)
	{
		// проверить наличие атрибутов
		if (attributes == null || attributes.length == 0) return this; 
        
        // создать набор атрибутов
        Map<Long, Attribute> result = new HashMap<Long, Attribute>(this.attributes); 

        // для всех атрибутов
        for (Attribute attribute : attributes) 
        {
            // добавить/заменить атрибут в набор
            result.put(attribute.type(), attribute);
        }
        // вернуть набор атрибутов
        return new Attributes(result); 
    }
}

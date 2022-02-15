package aladdin.asn1.iso;
import aladdin.asn1.*; 
import java.io.*;

// Attributes ::= SET OF Attribute

public final class Attributes extends Set<Attribute>
{
	// конструктор при раскодировании
	public Attributes(IEncodable encodable) throws IOException 
	{ 
		super(Attribute.class, encodable); 
	} 
	// конструктор при закодировании
	public Attributes(Attribute... values) 
	{
		super(Attribute.class, values); 
	} 
	// найти требуемый атрибут
	public final Attribute get(String oid) 
	{
		// для всех атрибутов
		for (Attribute attribute : this)
		{
			// проверить совпадение идентификатора
			if (attribute.type().value().equals(oid)) return attribute; 
		}
		return null; 
	}
    // найти требуемый атрибут
    public static IEncodable getAttributeValue(
        java.util.List<Attribute> attributes, String oid, int i) throws IOException
    {
        // для всех атрибутов
        for (Attribute attribute : attributes)
        {
            // сравнить идентификатор атрибута
            if (!attribute.type().value().equals(oid)) continue; 

            // проверить число значений атрибута
            if (attribute.values().size() <= i) return null; 
            
            // вернуть значение
            return attribute.values().get(i); 
        }
        return null; 
    }
    // добавить требуемый атрибут
    public static void setAttributeValues(
        java.util.List<Attribute> attributes, String oid, IEncodable... values) 
    {
        // указать значение атрибута
        Set<IEncodable> set = new Set<IEncodable>(IEncodable.class, values);
        
        // создать атрибут
        Attribute attribute = new Attribute(new ObjectIdentifier(oid), set); 
        
        // для всех атрибутов
        for (int i = 0; i < attributes.size(); i++)
        {
            // сравнить идентификатор атрибута
            if (!attributes.get(i).type().value().equals(oid)) continue; 
             
            // заменить атрибут в списке
            attributes.set(i, attribute); return; 
        }
        // добавить значение атрибута
        attributes.add(attribute); 
    }
}

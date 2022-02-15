package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import java.io.*; 

// RelativeDistinguishedName ::= SET OF AttributeTypeValue

public final class RelativeDistinguishedName extends Set<AttributeTypeValue>
{
	// конструктор при раскодировании
	public RelativeDistinguishedName(IEncodable encodable) throws IOException
	{
		super(AttributeTypeValue.class, encodable); 
	}
	// конструктор при закодировании
	public RelativeDistinguishedName(AttributeTypeValue... values) 
	{
		super(AttributeTypeValue.class, values); 
	}
	// найти требуемый атрибут
	public final AttributeTypeValue get(String oid) 
	{
		// для всех атрибутов
		for (AttributeTypeValue attribute : this)
		{
			// проверить совпадение идентификатора
			if (attribute.type().value().equals(oid)) return attribute; 
		}
		return null; 
	}
}

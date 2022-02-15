package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*; 

// SubjectDirectoryAttributes ::= SEQUENCE OF Attribute

public final class SubjectDirectoryAttributes extends Sequence<Attribute>
{
	// конструктор при раскодировании
	public SubjectDirectoryAttributes(IEncodable encodable) throws IOException
	{
		super(Attribute.class, encodable); 
	}
	// конструктор при закодировании
	public SubjectDirectoryAttributes(Attribute... values) 
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
}

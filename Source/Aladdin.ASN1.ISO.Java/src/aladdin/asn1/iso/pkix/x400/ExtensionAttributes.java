package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 
import java.io.*; 

// ExtensionAttributes ::= SET SIZE (1..ub-extension-attributes) OF ExtensionAttribute
// ub-extension-attributes INTEGER ::= 256

public final class ExtensionAttributes extends Set<ExtensionAttribute>
{
    private static final long serialVersionUID = -883031649270022894L;
    
	// конструктор при раскодировании
	public ExtensionAttributes(IEncodable encodable) throws IOException
	{ 
		super(ExtensionAttribute.class, encodable); 
		
		// проверить корректность
		if (size() <= 0 || size() > 256) throw new IOException(); 
	}
	// конструктор при закодировании
	public ExtensionAttributes(ExtensionAttribute... values) 
	{ 
		super(ExtensionAttribute.class, values); 
		
		// проверить корректность
		if (size() <= 0 || size() > 256) throw new IllegalArgumentException(); 
	}
	public final ExtensionAttribute getAttribute(int type)
	{
		// для всех атрибутов
		for (ExtensionAttribute attribute : this)
		{
			// проверить совпадение идентификатора
			if (attribute.extensionAttributeType().value().intValue() == type) return attribute; 
		}
		return null; 
	}
}

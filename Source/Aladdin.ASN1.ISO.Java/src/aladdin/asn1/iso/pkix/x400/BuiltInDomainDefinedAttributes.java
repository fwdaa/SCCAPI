package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 
import java.io.*; 

// BuiltInDomainDefinedAttributes ::= SEQUENCE SIZE (1..ub-domain-defined-attributes) OF BuiltInDomainDefinedAttribute
// ub-domain-defined-attributes INTEGER ::= 4

public final class BuiltInDomainDefinedAttributes extends Sequence<BuiltInDomainDefinedAttribute>
{
    private static final long serialVersionUID = 5132331948696895152L;
    
    // конструктор при раскодировании
    public BuiltInDomainDefinedAttributes(IEncodable encodable) throws IOException  
    { 
		// вызвать базовую функцию
		super(BuiltInDomainDefinedAttribute.class, encodable); 
        
		// проверить корректность
        if (size() <= 0 || size() > 4) throw new IOException(); 
    }
    // конструктор при закодировании
    public BuiltInDomainDefinedAttributes(BuiltInDomainDefinedAttribute... values) 
    { 
		// вызвать базовую функцию
		super(BuiltInDomainDefinedAttribute.class, values); 
        
		// проверить корректность
		if (size() <= 0 || size() > 4) throw new IllegalArgumentException(); 
    } 
    // найти требуемый атрибут
    public final BuiltInDomainDefinedAttribute get(String type) 
    {
		// для всех атрибутов
		for (BuiltInDomainDefinedAttribute attribute : this)
		{
			// проверить совпадение идентификатора
			if (attribute.type().str().equals(type)) return attribute; 
		}
		return null; 
    }
}

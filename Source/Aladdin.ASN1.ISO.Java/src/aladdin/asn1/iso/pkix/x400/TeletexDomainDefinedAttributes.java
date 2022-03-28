package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 
import java.io.*; 

// TeletexDomainDefinedAttributes ::= SEQUENCE SIZE (1..ub-domain-defined-attributes) OF TeletexDomainDefinedAttribute
// ub-domain-defined-attributes INTEGER ::= 4

public final class TeletexDomainDefinedAttributes extends Sequence<TeletexDomainDefinedAttribute>
{
    private static final long serialVersionUID = 5667628547359538429L;
    
	// конструктор при раскодировании
	public TeletexDomainDefinedAttributes(IEncodable encodable) throws IOException
	{ 
		super(TeletexDomainDefinedAttribute.class, encodable);  
		
		// проверить корректность
		if (size() <= 0 || size() > 4) throw new IOException(); 
	}
	// конструктор при закодировании
	public TeletexDomainDefinedAttributes(TeletexDomainDefinedAttribute... values) 
	{ 
		super(TeletexDomainDefinedAttribute.class, values);  
		
		// проверить корректность
		if (size() <= 0 || size() > 4) throw new IllegalArgumentException(); 
	}
}

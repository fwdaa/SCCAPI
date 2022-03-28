package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 
import java.io.*; 

//	TeletexDomainDefinedAttribute ::= SEQUENCE {
//		type  TeletexString (SIZE (1..ub-domain-defined-attribute-type-length)),
//		value TeletexString (SIZE (1..ub-domain-defined-attribute-value-length)) 
//	}
//	ub-domain-defined-attribute-type-length  INTEGER ::= 8
//	ub-domain-defined-attribute-value-length INTEGER ::= 128

public final class TeletexDomainDefinedAttribute extends Sequence<TeletexString>
{
    private static final long serialVersionUID = 1530091793988729823L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(TeletexString.class).factory(1,   8), Cast.N, Tag.ANY), 
		new ObjectInfo(new ObjectCreator(TeletexString.class).factory(1, 128), Cast.N, Tag.ANY), 
	}; 
	// конструктор при раскодировании
	public TeletexDomainDefinedAttribute(IEncodable encodable) throws IOException { super(encodable, info); }
	
	// конструктор при закодировании
	public TeletexDomainDefinedAttribute(TeletexString type, TeletexString value) 
	{
		super(info, type, value); 
	}
	public final TeletexString type ()	{ return get(0); }
	public final TeletexString value()	{ return get(1); }
}

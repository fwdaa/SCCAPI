package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import java.io.*; 

//	PolicyMapping ::= SEQUENCE {
//		issuerDomainPolicy      OBJECT IDENTIFIER,
//		subjectDomainPolicy     OBJECT IDENTIFIER 
//	}

public final class PolicyMapping extends Sequence<ObjectIdentifier>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public PolicyMapping(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public PolicyMapping(ObjectIdentifier issuerDomainPolicy, ObjectIdentifier subjectDomainPolicy) 
	{
		super(info, issuerDomainPolicy, subjectDomainPolicy); 
	}
	public final ObjectIdentifier issuerDomainPolicy () { return get(0); } 
	public final ObjectIdentifier subjectDomainPolicy() { return get(1); }
}

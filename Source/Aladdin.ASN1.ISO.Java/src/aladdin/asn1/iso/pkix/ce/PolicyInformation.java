package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import java.io.*; 

//	PolicyInformation ::= SEQUENCE {
//		policyIdentifier   OBJECT IDENTIFIER,
//		policyQualifiers   PolicyQualifierInfos OPTIONAL 
//	}

public final class PolicyInformation extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier       .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(PolicyQualifierInfos	.class).factory(), Cast.O), 
	}; 
	// конструктор при раскодировании
	public PolicyInformation(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public PolicyInformation(ObjectIdentifier policyIdentifier, 
		PolicyQualifierInfos policyQualifiers) 
	{
		super(info, policyIdentifier, policyQualifiers); 
	}
	public final ObjectIdentifier       policyIdentifier() { return (ObjectIdentifier    )get(0); } 
	public final PolicyQualifierInfos   policyQualifiers() { return (PolicyQualifierInfos)get(1); }
}

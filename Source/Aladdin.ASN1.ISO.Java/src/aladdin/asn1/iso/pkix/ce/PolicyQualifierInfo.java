package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import java.io.*; 

//	PolicyQualifierInfo ::= SEQUENCE {
//		policyQualifierId  OBJECT IDENTIFIER,
//		qualifier          ANY DEFINED BY policyQualifierId 
//	}

public final class PolicyQualifierInfo extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -1196182213265815207L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(    ImplicitCreator			            .factory  , Cast.N), 
	}; 
	public PolicyQualifierInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public PolicyQualifierInfo(ObjectIdentifier policyQualifierId, IEncodable qualifier) 
	{
		super(info, policyQualifierId, qualifier); 
	} 
	public final ObjectIdentifier	policyQualifierId() { return (ObjectIdentifier)get(0); } 
	public final IEncodable         qualifier		 () { return                   get(1); }
}

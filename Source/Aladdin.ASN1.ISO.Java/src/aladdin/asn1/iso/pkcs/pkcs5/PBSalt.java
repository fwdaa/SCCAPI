package aladdin.asn1.iso.pkcs.pkcs5;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 

//	SaltParameter ::= CHOICE {
//		specified	OCTET STRING,
//		otherSource AlgorithmIdentifier 
//	}

public final class PBSalt extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString            .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier	.class).factory(), Cast.N), 
	}; 
	// конструктор
	public PBSalt() { super(info); } 
}

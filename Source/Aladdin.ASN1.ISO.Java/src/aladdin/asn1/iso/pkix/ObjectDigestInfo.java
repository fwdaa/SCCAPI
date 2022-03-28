package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	ObjectDigestInfo    ::= SEQUENCE {
//		digestedObjectType  INTEGER,
//		otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
//		digestAlgorithm     AlgorithmIdentifier,
//		objectDigest        BIT STRING
//	}

public final class ObjectDigestInfo extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -5788724948362088969L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer            .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(ObjectIdentifier	.class).factory(), Cast.O), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(BitString          .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public ObjectDigestInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public ObjectDigestInfo(Integer digestedObjectType, 
		ObjectIdentifier otherObjectTypeID, AlgorithmIdentifier digestAlgorithm, 
		BitString objectDigest) 
	{
		super(info, digestedObjectType,	otherObjectTypeID, digestAlgorithm, objectDigest);
	}
	public final Integer                digestedObjectType() { return (Integer              )get(0); } 
	public final ObjectIdentifier       otherObjectTypeID () { return (ObjectIdentifier     )get(1); }
	public final AlgorithmIdentifier	digestAlgorithm	  () { return (AlgorithmIdentifier  )get(2); } 
	public final BitString              objectDigest	  () { return (BitString            )get(3); }
}

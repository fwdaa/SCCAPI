package aladdin.asn1.iso.pkcs.pkcs5;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	PBMParameter ::= SEQUENCE {
//		salt                OCTET STRING,
//		owf                 AlgorithmIdentifier,
//		iterationCount      INTEGER,
//		mac                 AlgorithmIdentifier
//	}

public final class PBMParameter extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 5993699113930333145L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString		.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer            .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public PBMParameter(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public PBMParameter(OctetString salt, AlgorithmIdentifier owf, 
		Integer iterationCount, AlgorithmIdentifier mac) 
	{
		super(info, salt, owf, iterationCount, mac); 
	}
	public final OctetString            salt			() { return (OctetString        )get(0); } 
	public final AlgorithmIdentifier	owf				() { return (AlgorithmIdentifier)get(1); } 
	public final Integer                iterationCount	() { return (Integer            )get(2); }
	public final AlgorithmIdentifier	mac				() { return (AlgorithmIdentifier)get(3); } 
}

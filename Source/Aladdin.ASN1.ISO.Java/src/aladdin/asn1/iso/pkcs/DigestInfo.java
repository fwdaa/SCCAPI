package aladdin.asn1.iso.pkcs;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*;

//	DigestInfo ::= SEQUENCE {
//		digestAlgorithm AlgorithmIdentifier,
//		digest          OCTET STRING
//	}

public final class DigestInfo extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -5099077783705557039L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString		.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public DigestInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public DigestInfo(AlgorithmIdentifier digestAlgorithm, OctetString digest) 
	{
		super(info, digestAlgorithm, digest); 
	}
	public final AlgorithmIdentifier    digestAlgorithm	() { return (AlgorithmIdentifier)get(0); }
	public final OctetString            digest			() { return (OctetString        )get(1); }
}

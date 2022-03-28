package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*;

//	DigestedData ::= SEQUENCE {
//		version				INTEGER,
//		digestAlgorithm		AlgorithmIdentifier,
//		encapContentInfo	EncapsulatedContentInfo,
//		digest				OCTET STRING 
//	}

public final class DigestedData extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -416956041158823784L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer                .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier	.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(EncapsulatedContentInfo.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString			.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public DigestedData(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public DigestedData(Integer version, AlgorithmIdentifier digestAlgorithm, 
		EncapsulatedContentInfo encapContentInfo, OctetString digest)
	{
		super(info, version, digestAlgorithm, encapContentInfo, digest); 
	}
	public final Integer                    version			() { return (Integer                )get(0); } 
	public final AlgorithmIdentifier		digestAlgorithm	() { return (AlgorithmIdentifier	)get(1); }
	public final EncapsulatedContentInfo	encapContentInfo() { return (EncapsulatedContentInfo)get(2); } 
	public final OctetString                digest			() { return (OctetString            )get(3); }
}

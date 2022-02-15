package aladdin.asn1.iso.pkcs.pkcs8;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*; 

// PrivateKeyInfo ::= SEQUENCE {
//		version								INTEGER,
//		privateKeyAlgorithm					AlgorithmIdentifier,
//		privateKey							OCTET STRING,
//		attributes			[0] IMPLICIT	Attributes		OPTIONAL
//	}

public final class PrivateKeyInfo extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer            .class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(OctetString		.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(Attributes			.class).factory(), Cast.O,	Tag.context(0)	), 
	}; 
	// конструктор при раскодировании
	public PrivateKeyInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public PrivateKeyInfo(Integer version, 
		AlgorithmIdentifier privateKeyAlgorithm, OctetString privateKey, 
		Attributes attributes) 
	{
		super(info, version, privateKeyAlgorithm, privateKey, attributes); 
	}
	public final Integer                version				() { return (Integer            )get(0); } 
	public final AlgorithmIdentifier	privateKeyAlgorithm	() { return (AlgorithmIdentifier)get(1); }
	public final OctetString            privateKey			() { return (OctetString        )get(2); } 
	public final Attributes             attributes			() { return (Attributes			)get(3); }
}

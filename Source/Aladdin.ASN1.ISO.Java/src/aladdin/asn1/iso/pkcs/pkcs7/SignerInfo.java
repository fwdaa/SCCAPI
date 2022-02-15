package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	SignerInfo ::= SEQUENCE {
//		version								INTEGER,
//		sid									SignerIdentifier,
//		digestAlgorithm						AlgorithmIdentifier,
//		signedAttrs			[0] IMPLICIT	Attributes				OPTIONAL,
//		signatureAlgorithm					AlgorithmIdentifier,
//		signature							OCTET STRING,
//		unsignedAttrs		[1] IMPLICIT	Attributes				OPTIONAL 
//	}

public final class SignerInfo extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer            .class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ChoiceCreator(SignerIdentifier	.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(Attributes			.class).factory(), Cast.O,	Tag.context(0)	), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(OctetString		.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(Attributes			.class).factory(), Cast.O,	Tag.context(1)	), 
	}; 
	// конструктор при раскодировании
	public SignerInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public SignerInfo(Integer version, IEncodable sid, 
		AlgorithmIdentifier digestAlgorithm, Attributes signedAttrs, 
		AlgorithmIdentifier signatureAlgorithm, OctetString signature, 
		Attributes unsignedAttrs) 
	{
		super(info, version, sid, digestAlgorithm, signedAttrs, 
			signatureAlgorithm, signature, unsignedAttrs); 
	}
	public final Integer                version				() { return (Integer            )get(0); } 
	public final IEncodable             sid					() { return						 get(1); }
	public final AlgorithmIdentifier	digestAlgorithm		() { return (AlgorithmIdentifier)get(2); } 
	public final Attributes             signedAttrs			() { return (Attributes			)get(3); }
	public final AlgorithmIdentifier	signatureAlgorithm	() { return (AlgorithmIdentifier)get(4); } 
	public final OctetString            signature			() { return (OctetString		)get(5); }
	public final Attributes             unsignedAttrs		() { return (Attributes			)get(6); } 
}

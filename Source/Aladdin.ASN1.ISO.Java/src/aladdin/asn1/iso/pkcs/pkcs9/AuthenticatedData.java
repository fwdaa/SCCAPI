package aladdin.asn1.iso.pkcs.pkcs9;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkcs.pkcs7.*; 
import java.io.*;

//	AuthenticatedData ::= SEQUENCE {
//		version							INTEGER,
//		originatorInfo	[0] IMPLICIT	OriginatorInfo			OPTIONAL,
//		recipientInfos					RecipientInfos,
//		macAlgorithm					AlgorithmIdentifier,
//		digestAlgorithm [1] IMPLICIT	AlgorithmIdentifier		OPTIONAL,
//		encapContentInfo				EncapsulatedContentInfo,
//		authAttrs		[2] IMPLICIT	Attributes				OPTIONAL,
//		mac								OCTET STRING,
//		unauthAttrs		[3] IMPLICIT	Attributes				OPTIONAL 
//}

public class AuthenticatedData extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer                .class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(OriginatorInfo			.class).factory(), Cast.O,	Tag.context(0)	), 
		new ObjectInfo(new ObjectCreator(RecipientInfos			.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier	.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier	.class).factory(), Cast.O,	Tag.context(1)	), 
		new ObjectInfo(new ObjectCreator(EncapsulatedContentInfo.class).factory(), Cast.N,	Tag.ANY			),	
		new ObjectInfo(new ObjectCreator(Attributes				.class).factory(), Cast.O,	Tag.context(2)	), 
		new ObjectInfo(new ObjectCreator(OctetString			.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(Attributes				.class).factory(), Cast.O,	Tag.context(3)	), 
	}; 
	// конструктор при раскодировании
	public AuthenticatedData(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public AuthenticatedData(Integer version, OriginatorInfo originatorInfo, 
		RecipientInfos recipientInfos, AlgorithmIdentifier macAlgorithm, 
		AlgorithmIdentifier digestAlgorithm, EncapsulatedContentInfo encapContentInfo, 
		Attributes authAttrs, OctetString mac, Attributes unauthAttrs) 
	{
		super(info, version, originatorInfo, recipientInfos, macAlgorithm, 
			digestAlgorithm, encapContentInfo, authAttrs, mac, unauthAttrs); 
	}
	public final Integer                    version			() { return (Integer                )get(0); } 
	public final OriginatorInfo             originatorInfo	() { return (OriginatorInfo			)get(1); }
	public final RecipientInfos             recipientInfos	() { return (RecipientInfos			)get(2); } 
	public final AlgorithmIdentifier		macAlgorithm	() { return (AlgorithmIdentifier	)get(3); }
	public final AlgorithmIdentifier		digestAlgorithm	() { return (AlgorithmIdentifier	)get(4); }
	public final EncapsulatedContentInfo	encapContentInfo() { return (EncapsulatedContentInfo)get(5); } 
	public final Attributes                 authAttrs		() { return (Attributes				)get(6); }
	public final OctetString                mac				() { return (OctetString            )get(7); } 
	public final Attributes                 unauthAttrs		() { return (Attributes				)get(8); }
}

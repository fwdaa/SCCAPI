package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	KeyAgreeRecipientInfo ::= SEQUENCE {
//		version									INTEGER,
//		originator				[0] EXPLICIT	OriginatorIdentifierOrKey,
//		ukm						[1] EXPLICIT	OCTET STRING			OPTIONAL,
//		keyEncryptionAlgorithm					AlgorithmIdentifier,
//		recipientEncryptedKeys					RecipientEncryptedKeys 
//	}

public final class KeyAgreeRecipientInfo extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer                    .class).factory(), Cast.N,		Tag.ANY			), 
		new ObjectInfo(new ChoiceCreator(OriginatorIdentifierOrKey  .class).factory(), Cast.E,		Tag.context(0)	), 
		new ObjectInfo(new ObjectCreator(OctetString                .class).factory(), Cast.EO,		Tag.context(1)	), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier		.class).factory(), Cast.N,		Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(RecipientEncryptedKeys     .class).factory(), Cast.N,		Tag.ANY			), 
	}; 
	// конструктор при раскодировании
	public KeyAgreeRecipientInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public KeyAgreeRecipientInfo(Integer version, IEncodable originator, 
		OctetString ukm, AlgorithmIdentifier keyEncryptionAlgorithm, 
		RecipientEncryptedKeys recipientEncryptedKeys) 
	{
		super(info, version, originator, ukm, keyEncryptionAlgorithm, recipientEncryptedKeys); 
	}
	public final Integer                version					() { return (Integer                )get(0); } 
	public final IEncodable             originator				() { return							 get(1); }
	public final OctetString            ukm						() { return (OctetString            )get(2); } 
	public final AlgorithmIdentifier	keyEncryptionAlgorithm	() { return (AlgorithmIdentifier	)get(3); }
	public final RecipientEncryptedKeys	recipientEncryptedKeys	() { return (RecipientEncryptedKeys	)get(4); }
}

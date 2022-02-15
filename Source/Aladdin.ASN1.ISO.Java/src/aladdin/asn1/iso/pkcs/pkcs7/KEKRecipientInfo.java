package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	KEKRecipientInfo ::= SEQUENCE {
//		version					INTEGER,
//		kekid					KEKIdentifier,
//		keyEncryptionAlgorithm	AlgorithmIdentifier,
//		encryptedKey			OCTET STRING 
//	}

public final class KEKRecipientInfo extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer            .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(KEKIdentifier		.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString		.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public KEKRecipientInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public KEKRecipientInfo(Integer version, KEKIdentifier kekid, 
		AlgorithmIdentifier keyEncryptionAlgorithm, OctetString encryptedKey) 
	{
		super(info, version, kekid, keyEncryptionAlgorithm, encryptedKey); 
	}
	public final Integer                version					() { return (Integer            )get(0); } 
	public final KEKIdentifier          kekId					() { return (KEKIdentifier		)get(1); }
	public final AlgorithmIdentifier	keyEncryptionAlgorithm	() { return (AlgorithmIdentifier)get(2); }
	public final OctetString            encryptedKey			() { return (OctetString        )get(3); } 
}

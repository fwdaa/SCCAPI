package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	KeyTransRecipientInfo ::= SEQUENCE {
//		version					INTEGER,
//		rid						RecipientIdentifier,
//		keyEncryptionAlgorithm	AlgorithmIdentifier,
//		encryptedKey			OCTET STRING 
//	}

public final class KeyTransRecipientInfo extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -4090114070415795974L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer            .class).factory(), Cast.N), 
		new ObjectInfo(new ChoiceCreator(RecipientIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString		.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public KeyTransRecipientInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public KeyTransRecipientInfo(Integer version, IEncodable rid, 
		AlgorithmIdentifier keyEncryptionAlgorithm, OctetString encryptedKey) 
	{
		super(info, version, rid, keyEncryptionAlgorithm, encryptedKey); 
	}
	public final Integer                version					() { return (Integer            )get(0); } 
	public final IEncodable             rid						() { return						 get(1); }
	public final AlgorithmIdentifier	keyEncryptionAlgorithm	() { return (AlgorithmIdentifier)get(2); } 
	public final OctetString            encryptedKey			() { return (OctetString        )get(3); }
}

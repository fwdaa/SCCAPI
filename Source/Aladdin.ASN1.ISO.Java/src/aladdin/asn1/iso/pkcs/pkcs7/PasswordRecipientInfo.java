package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	PasswordRecipientInfo ::= SEQUENCE {
//		version								INTEGER,
//		keyDerivationAlgorithm [0] IMPLICIT AlgorithmIdentifier OPTIONAL,
//		keyEncryptionAlgorithm				AlgorithmIdentifier,
//		encryptedKey						OCTET STRING 
//	}

public final class PasswordRecipientInfo extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -1420477541556551533L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer            .class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.O,	Tag.context(0)	), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(OctetString		.class).factory(), Cast.N,	Tag.ANY			), 
	}; 
	// конструктор при раскодировании
	public PasswordRecipientInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public PasswordRecipientInfo(Integer version, 
		AlgorithmIdentifier keyDerivationAlgorithm, 
		AlgorithmIdentifier keyEncryptionAlgorithm, OctetString encryptedKey) 
	{
		super(info, version, keyDerivationAlgorithm, keyEncryptionAlgorithm, encryptedKey); 
	}
	public final Integer                version					() { return (Integer            )get(0); } 
	public final AlgorithmIdentifier	keyDerivationAlgorithm	() { return (AlgorithmIdentifier)get(1); }
	public final AlgorithmIdentifier	keyEncryptionAlgorithm	() { return (AlgorithmIdentifier)get(2); }
	public final OctetString            encryptedKey			() { return (OctetString        )get(3); } 
}

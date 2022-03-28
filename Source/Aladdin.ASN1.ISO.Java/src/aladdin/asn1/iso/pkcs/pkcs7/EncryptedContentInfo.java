package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*;

//	EncryptedContentInfo ::= SEQUENCE {
//		contentType									OBJECT IDENTIFIER,
//		contentEncryptionAlgorithm					AlgorithmIdentifier,
//		encryptedContent			[0] IMPLICIT	OCTET STRING	OPTIONAL 
//	}

public final class EncryptedContentInfo extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 8349643707246449452L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier	.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(OctetString		.class).factory(), Cast.O,	Tag.context(0)	), 
	}; 
	// конструктор при раскодировании
	public EncryptedContentInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public EncryptedContentInfo(ObjectIdentifier contentType, 
		AlgorithmIdentifier contentEncryptionAlgorithm, OctetString encryptedContent) 
	{
		super(info, contentType, contentEncryptionAlgorithm, encryptedContent); 	
	}
	public final ObjectIdentifier       contentType					() { return (ObjectIdentifier	)get(0); } 
	public final AlgorithmIdentifier	contentEncryptionAlgorithm	() { return (AlgorithmIdentifier)get(1); }
	public final OctetString            encryptedContent			() { return (OctetString		)get(2); }
}

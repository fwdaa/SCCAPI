package aladdin.asn1.iso.pkcs.pkcs8;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*;

//	EncryptedPrivateKeyInfo ::= SEQUENCE {
//		encryptionAlgorithm	AlgorithmIdentifier,
//		encryptedData		OCTET STRING
//	}

public final class EncryptedPrivateKeyInfo extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString		.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public EncryptedPrivateKeyInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public EncryptedPrivateKeyInfo(AlgorithmIdentifier encryptionAlgorithm, 
		OctetString encryptedData) 
	{
		super(info, encryptionAlgorithm, encryptedData); 
	}
	public final AlgorithmIdentifier	encryptionAlgorithm() { return (AlgorithmIdentifier	)get(0); } 
	public final OctetString            encryptedData	   () { return (OctetString         )get(1); }
}

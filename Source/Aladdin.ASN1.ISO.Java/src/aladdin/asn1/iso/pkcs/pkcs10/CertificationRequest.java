package aladdin.asn1.iso.pkcs.pkcs10;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*;

//	CertificationRequest ::= SEQUENCE {
//		certificationRequestInfo	CertificationRequestInfo,
//		signatureAlgorithm			AlgorithmIdentifier,
//		signature					BIT STRING
//	}

public final class CertificationRequest extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -5485176563086634825L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(CertificationRequestInfo	.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier		.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(BitString                  .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public CertificationRequest(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public CertificationRequest(CertificationRequestInfo certificationRequestInfo, 
		AlgorithmIdentifier signatureAlgorithm, BitString signature) 
	{
		super(info, certificationRequestInfo, signatureAlgorithm, signature); 
	}
	public final CertificationRequestInfo   certificationRequestInfo() { return (CertificationRequestInfo	)get(0); } 
	public final AlgorithmIdentifier		signatureAlgorithm		() { return (AlgorithmIdentifier		)get(1); } 
	public final BitString                  signature				() { return (BitString                  )get(2); } 
}

package aladdin.asn1.iso.pkcs.pkcs6;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*;

//	ExtendedCertificate ::= SEQUENCE {
//		extendedCertificateInfo ExtendedCertificateInfo,
//		signatureAlgorithm		AlgorithmIdentifier,
//		signature				BIT STRING
//	}

public final class ExtendedCertificate extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ExtendedCertificateInfo.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier	.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(BitString              .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public ExtendedCertificate(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public ExtendedCertificate(ExtendedCertificateInfo extendedCertificateInfo, 
		AlgorithmIdentifier signatureAlgorithm, BitString signature) 
	{
		super(info, extendedCertificateInfo, signatureAlgorithm, signature); 
	}
	public final ExtendedCertificateInfo	extendedCertificateInfo	() { return (ExtendedCertificateInfo)get(0); } 
	public final AlgorithmIdentifier		signatureAlgorithm		() { return (AlgorithmIdentifier	)get(1); }
	public final BitString                  signature				() { return (BitString              )get(2); }
}

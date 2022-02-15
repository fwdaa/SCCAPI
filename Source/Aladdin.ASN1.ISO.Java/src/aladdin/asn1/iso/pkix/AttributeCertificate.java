package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*;

//	AttributeCertificate ::= SEQUENCE {
//		acinfo               AttributeCertificateInfo,
//		signatureAlgorithm   AlgorithmIdentifier,
//		signatureValue       BIT STRING
//	}

public final class AttributeCertificate extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(AttributeCertificateInfo	.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier		.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(BitString                  .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public AttributeCertificate(IEncodable encodable) throws IOException { super(encodable, info); } 

	// конструктор при закодировании
	public AttributeCertificate(AttributeCertificateInfo acinfo, 
		AlgorithmIdentifier signatureAlgorithm, BitString signatureValue) 
	{
		super(info, acinfo, signatureAlgorithm, signatureValue); 
	} 
	public final AttributeCertificateInfo	acInfo			  () { return (AttributeCertificateInfo)get(0); } 
	public final AlgorithmIdentifier		signatureAlgorithm() { return (AlgorithmIdentifier	   )get(1); }
	public final BitString                  signatureValue	  () { return (BitString               )get(2); }
}

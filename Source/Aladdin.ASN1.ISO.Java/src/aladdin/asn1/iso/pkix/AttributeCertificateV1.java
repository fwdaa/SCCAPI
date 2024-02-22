package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*;

//	AttributeCertificateV1 ::= SEQUENCE {
//		acinfo               AttributeCertificateInfoV1,
//		signatureAlgorithm   AlgorithmIdentifier,
//		signatureValue       BIT STRING
//	}

public final class AttributeCertificateV1 extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 2531399348478191157L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(AttributeCertificateInfoV1	.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier		.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(BitString                  .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public AttributeCertificateV1(IEncodable encodable) throws IOException { super(encodable, info); } 

	// конструктор при закодировании
	public AttributeCertificateV1(AttributeCertificateInfoV1 acinfo, 
		AlgorithmIdentifier signatureAlgorithm, BitString signatureValue) 
	{
		super(info, acinfo, signatureAlgorithm, signatureValue); 
	} 
	public final AttributeCertificateInfoV1	acInfo			  () { return (AttributeCertificateInfoV1)get(0); } 
	public final AlgorithmIdentifier		signatureAlgorithm() { return (AlgorithmIdentifier		 )get(1); }
	public final BitString                  signatureValue	  () { return (BitString                 )get(2); }
}

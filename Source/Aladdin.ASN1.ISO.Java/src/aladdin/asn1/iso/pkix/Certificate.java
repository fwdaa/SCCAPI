package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*;

//	Certificate  ::=  SEQUENCE  {
//		tbsCertificate       TBSCertificate,
//		signatureAlgorithm   AlgorithmIdentifier,
//		signature            BIT STRING  
//	}

public final class Certificate extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(TBSCertificate     .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(BitString          .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public Certificate(IEncodable encodable) throws IOException { super(encodable, info); } 

	// конструктор при закодировании
	public Certificate(TBSCertificate tbsCertificate, 
		AlgorithmIdentifier signatureAlgorithm, BitString signature) 
	{
		super(info, tbsCertificate, signatureAlgorithm, signature); 
	}
	public final TBSCertificate         tbsCertificate    () { return (TBSCertificate       )get(0); } 
	public final AlgorithmIdentifier	signatureAlgorithm() { return (AlgorithmIdentifier  )get(1); }
	public final BitString              signature		  () { return (BitString            )get(2); }
}

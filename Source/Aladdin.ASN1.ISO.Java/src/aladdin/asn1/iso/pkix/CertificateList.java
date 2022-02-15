package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*;

//	CertificateList  ::=  SEQUENCE  {
//		tbsCertList          TBSCertList,
//		signatureAlgorithm   AlgorithmIdentifier,
//		signature            BIT STRING   
//	}

public final class CertificateList extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(TBSCertificateList .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(BitString          .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public CertificateList(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public CertificateList(TBSCertificateList tbsCertList, 
		AlgorithmIdentifier signatureAlgorithm, BitString signature) 
	{
		super(info, tbsCertList, signatureAlgorithm, signature); 
	}
	public final TBSCertificateList     tbsCertList			() { return (TBSCertificateList	)get(0); } 
	public final AlgorithmIdentifier	signatureAlgorithm	() { return (AlgorithmIdentifier)get(1); }
	public final BitString              signature			() { return (BitString          )get(2); }
}


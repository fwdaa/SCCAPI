package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.*; 
import java.io.*; 

//	TargetCert  ::= SEQUENCE {
//		targetCertificate  IssuerSerial,
//		targetName         GeneralName		OPTIONAL,
//		certDigestInfo     ObjectDigestInfo	OPTIONAL
//	}

public final class TargetCert extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 1020913941254362662L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(IssuerSerial		.class).factory(), Cast.N), 
		new ObjectInfo(new ChoiceCreator(GeneralName		.class).factory(), Cast.O), 
		new ObjectInfo(new ObjectCreator(ObjectDigestInfo	.class).factory(), Cast.O), 
	}; 
	// конструктор при раскодировании
	public TargetCert(IEncodable encodable) throws IOException 
	{
		super(encodable, info); 
	}
	// конструктор при закодировании
	public TargetCert(IssuerSerial targetCertificate, IEncodable targetName, 
		ObjectDigestInfo certDigestInfo) 
	{
		super(info, targetCertificate, targetName, certDigestInfo); 
	}
	public final IssuerSerial		targetCertificate()	{ return (IssuerSerial		)get(0); } 
	public final IEncodable         targetName		 ()	{ return                     get(1); }
	public final ObjectDigestInfo	certDigestInfo	 ()	{ return (ObjectDigestInfo	)get(2); }
}

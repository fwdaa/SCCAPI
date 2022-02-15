package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*; 


//	OriginatorInfo ::= SEQUENCE {
//		certs	[0] IMPLICIT CertificateSet			OPTIONAL,
//		crls	[1] IMPLICIT RevocationInfoChoices	OPTIONAL 
//	}

public final class OriginatorInfo extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(CertificateSet         .class).factory(), Cast.O, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(RevocationInfoChoices  .class).factory(), Cast.O, Tag.context(1)), 
	}; 
	// конструктор при раскодировании
	public OriginatorInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public OriginatorInfo(CertificateSet certs, RevocationInfoChoices crls) 
	{
		super(info, certs, crls); 
	}
	public final CertificateSet			certs() { return (CertificateSet		)get(0); } 
	public final RevocationInfoChoices	crls () { return (RevocationInfoChoices	)get(1); }
}

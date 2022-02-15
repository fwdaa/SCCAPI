package aladdin.asn1.iso;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.iso.pkcs.pkcs6.*; 

//	CertificateChoices ::= CHOICE {
//		certificate						 Certificate,
//		extendedCertificate [0] IMPLICIT ExtendedCertificate,
//		v1AttrCert			[1] IMPLICIT AttributeCertificateV1,      
//		v2AttrCert			[2] IMPLICIT AttributeCertificate,
//		other				[3] IMPLICIT OtherCertificateFormat 
//	}

public final class CertificateChoices extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Certificate			.class).factory(), Cast.N, Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(ExtendedCertificate	.class).factory(), Cast.N, Tag.context(0)	), 
		new ObjectInfo(new ObjectCreator(AttributeCertificateV1	.class).factory(), Cast.N, Tag.context(1)	),  
		new ObjectInfo(new ObjectCreator(AttributeCertificate	.class).factory(), Cast.N, Tag.context(2)	),  
		new ObjectInfo(new ObjectCreator(OtherCertificateFormat	.class).factory(), Cast.N, Tag.context(3)	),  
	}; 
	// конструктор
	public CertificateChoices() { super(info); } 
}

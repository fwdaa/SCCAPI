package aladdin.asn1.iso.pkcs.pkcs6;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.*; 

//	ExtendedCertificateOrCertificate ::= CHOICE {
//		certificate							Certificate,
//		extendedCertificate [0] IMPLICIT	ExtendedCertificate 
//	}

public final class ExtendedCertificateOrCertificate extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Certificate			.class).factory(), Cast.N, Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(ExtendedCertificate	.class).factory(), Cast.N, Tag.context(0)	), 
	}; 
	// конструктор
	public ExtendedCertificateOrCertificate() { super(info); } 
}

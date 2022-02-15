package aladdin.asn1.iso;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.*; 

//	RevocationInfoChoice ::= CHOICE {
//		crl					CertificateList,
//		other [1] IMPLICIT	OtherRevocationInfoFormat 
//}

public final class RevocationInfoChoice extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(CertificateList		  .class).factory(), Cast.N, Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(OtherRevocationInfoFormat.class).factory(), Cast.N, Tag.context(0)	), 
	}; 
	// конструктор
	public RevocationInfoChoice() { super(info); } 
}

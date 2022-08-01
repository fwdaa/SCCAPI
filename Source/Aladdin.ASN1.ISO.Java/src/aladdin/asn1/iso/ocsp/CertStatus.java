package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;

// CertStatus ::= CHOICE {
//      good    [0] IMPLICIT NULL,
//      revoked [1] IMPLICIT RevokedInfo,
//		unknown [2] IMPLICIT NULL
// }

public final class CertStatus extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Null       .class).factory(), Cast.N, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(RevokedInfo.class).factory(), Cast.N, Tag.context(1)), 
		new ObjectInfo(new ObjectCreator(Null       .class).factory(), Cast.N, Tag.context(2)), 
	}; 
	// конструктор
	public CertStatus() { super(info); } 
}

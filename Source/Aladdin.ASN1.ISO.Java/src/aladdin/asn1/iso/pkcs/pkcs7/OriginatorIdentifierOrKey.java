package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.*; 

//	OriginatorIdentifierOrKey ::= CHOICE {
//		issuerSerialNumber					 IssuerSerialNumber,
//		subjectKeyIdentifier	[0] IMPLICIT OCTET STRING,
//		originatorKey			[1] IMPLICIT SubjectPublicKeyInfo 
//	}

public final class OriginatorIdentifierOrKey extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(IssuerSerialNumber     .class).factory(), Cast.N, Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(OctetString            .class).factory(), Cast.N, Tag.context(0)	), 
		new ObjectInfo(new ObjectCreator(SubjectPublicKeyInfo	.class).factory(), Cast.N, Tag.context(1)	), 
	}; 
	// конструктор
	public OriginatorIdentifierOrKey() { super(info); } 
}

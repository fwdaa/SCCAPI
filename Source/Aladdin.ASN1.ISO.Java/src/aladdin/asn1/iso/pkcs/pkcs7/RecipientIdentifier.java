package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.*; 

//	RecipientIdentifier ::= CHOICE {
//		issuerSerialNumber					 IssuerSerialNumber,
//		subjectKeyIdentifier	[0] IMPLICIT OCTET STRING
//	}

public final class RecipientIdentifier extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(IssuerSerialNumber	.class).factory(), Cast.N, Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(OctetString		.class).factory(), Cast.N, Tag.context(0)	), 
	}; 
	// конструктор
	public RecipientIdentifier() { super(info); } 
}

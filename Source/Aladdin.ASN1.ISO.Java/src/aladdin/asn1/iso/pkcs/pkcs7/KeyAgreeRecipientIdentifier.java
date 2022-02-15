package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.*; 

//	KeyAgreeRecipientIdentifier ::= CHOICE {
//		issuerSerialNumber				 IssuerSerialNumber,
//		rKeyId				[0] IMPLICIT RecipientKeyIdentifier 
//	}

public class KeyAgreeRecipientIdentifier extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(IssuerSerialNumber		.class).factory(), Cast.N, Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(RecipientKeyIdentifier	.class).factory(), Cast.N, Tag.context(0)	), 
	}; 
	// конструктор
	public KeyAgreeRecipientIdentifier() { super(info); } 
}

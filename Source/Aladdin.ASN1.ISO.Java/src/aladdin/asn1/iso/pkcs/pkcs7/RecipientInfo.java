package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 

//	RecipientInfo ::= CHOICE {
//		ktri					KeyTransRecipientInfo,
//		kari	[1] IMPLICIT	KeyAgreeRecipientInfo,
//		kekri	[2] IMPLICIT	KEKRecipientInfo,
//		pwri	[3] IMPLICIT	PasswordRecipientInfo,
//		ori		[4] IMPLICIT	OtherRecipientInfo 
//	}

public final class RecipientInfo extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(KeyTransRecipientInfo  .class).factory(), Cast.N, Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(KeyAgreeRecipientInfo  .class).factory(), Cast.N, Tag.context(1)	), 
		new ObjectInfo(new ObjectCreator(KEKRecipientInfo		.class).factory(), Cast.N, Tag.context(2)	),  
		new ObjectInfo(new ObjectCreator(PasswordRecipientInfo  .class).factory(), Cast.N, Tag.context(3)	),  
		new ObjectInfo(new ObjectCreator(OtherRecipientInfo     .class).factory(), Cast.N, Tag.context(4)	),  
	}; 
	// конструктор
	public RecipientInfo() { super(info); } 
}

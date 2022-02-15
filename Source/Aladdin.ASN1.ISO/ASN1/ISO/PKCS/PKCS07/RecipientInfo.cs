using System;

//	RecipientInfo ::= CHOICE {
//		ktri					KeyTransRecipientInfo,
//		kari	[1] IMPLICIT	KeyAgreeRecipientInfo,
//		kekri	[2] IMPLICIT	KEKRecipientInfo,
//		pwri	[3] IMPLICIT	PasswordRecipientInfo,
//		ori		[4] IMPLICIT	OtherRecipientInfo 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	public class RecipientInfo : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<KeyTransRecipientInfo	>().Factory(), Cast.N, Tag.Any			), 
			new ObjectInfo(new ObjectCreator<KeyAgreeRecipientInfo	>().Factory(), Cast.N, Tag.Context(1)	), 
			new ObjectInfo(new ObjectCreator<KEKRecipientInfo		>().Factory(), Cast.N, Tag.Context(2)	),  
			new ObjectInfo(new ObjectCreator<PasswordRecipientInfo	>().Factory(), Cast.N, Tag.Context(3)	),  
			new ObjectInfo(new ObjectCreator<OtherRecipientInfo		>().Factory(), Cast.N, Tag.Context(4)	),  
		}; 
		// конструктор
		public RecipientInfo() : base(info) {} 
	}
}

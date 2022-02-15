using System;

//	KeyAgreeRecipientIdentifier ::= CHOICE {
//		issuerSerialNumber				 IssuerSerialNumber,
//		rKeyId				[0] IMPLICIT RecipientKeyIdentifier 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	public class KeyAgreeRecipientIdentifier : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<PKIX.IssuerSerialNumber>().Factory(), Cast.N, Tag.Any			), 
			new ObjectInfo(new ObjectCreator<RecipientKeyIdentifier	>().Factory(), Cast.N, Tag.Context(0)	), 
		}; 
		// конструктор
		public KeyAgreeRecipientIdentifier() : base(info) {} 
	}
}

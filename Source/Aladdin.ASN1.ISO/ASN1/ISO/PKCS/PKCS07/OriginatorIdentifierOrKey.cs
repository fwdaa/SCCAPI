using System;

//	OriginatorIdentifierOrKey ::= CHOICE {
//		issuerSerialNumber					 IssuerSerialNumber,
//		subjectKeyIdentifier	[0] IMPLICIT OCTET STRING,
//		originatorKey			[1] IMPLICIT SubjectPublicKeyInfo 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	public class OriginatorIdentifierOrKey : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<PKIX.IssuerSerialNumber	>().Factory(), Cast.N, Tag.Any			), 
			new ObjectInfo(new ObjectCreator<OctetString				>().Factory(), Cast.N, Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<PKIX.SubjectPublicKeyInfo  >().Factory(), Cast.N, Tag.Context(1)	), 
		}; 
		// конструктор
		public OriginatorIdentifierOrKey() : base(info) {} 
	}
}

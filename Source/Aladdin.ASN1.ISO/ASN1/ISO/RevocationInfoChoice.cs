using System;

//	RevocationInfoChoice ::= CHOICE {
//		crl					CertificateList,
//		other [1] IMPLICIT	OtherRevocationInfoFormat 
//}

namespace Aladdin.ASN1.ISO
{
	public class RevocationInfoChoice : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<PKIX.CertificateList		>().Factory(), Cast.N, Tag.Any			), 
			new ObjectInfo(new ObjectCreator<OtherRevocationInfoFormat  >().Factory(), Cast.N, Tag.Context(0)	), 
		}; 
		// конструктор
		public RevocationInfoChoice() : base(info) {} 
	}
}

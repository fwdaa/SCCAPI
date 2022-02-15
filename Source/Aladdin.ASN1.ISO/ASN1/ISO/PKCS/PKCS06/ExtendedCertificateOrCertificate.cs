using System;

//	ExtendedCertificateOrCertificate ::= CHOICE {
//		certificate							Certificate,
//		extendedCertificate [0] IMPLICIT	ExtendedCertificate 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS6
{
	public class ExtendedCertificateOrCertificate : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<PKIX.Certificate	>().Factory(), Cast.N, Tag.Any			), 
			new ObjectInfo(new ObjectCreator<ExtendedCertificate>().Factory(), Cast.N, Tag.Context(0)	), 
		}; 
		// конструктор
		public ExtendedCertificateOrCertificate() : base(info) {} 
	}
}

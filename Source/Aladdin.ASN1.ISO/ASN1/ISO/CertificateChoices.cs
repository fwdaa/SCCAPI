using System;

//	CertificateChoices ::= CHOICE {
//		certificate						 Certificate,
//		extendedCertificate [0] IMPLICIT ExtendedCertificate,
//		v1AttrCert			[1] IMPLICIT AttributeCertificateV1,      
//		v2AttrCert			[2] IMPLICIT AttributeCertificate,
//		other				[3] IMPLICIT OtherCertificateFormat 
//	}

namespace Aladdin.ASN1.ISO
{
	public class CertificateChoices : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<PKIX.Certificate				>().Factory(), Cast.N, Tag.Any			), 
			new ObjectInfo(new ObjectCreator<PKCS.PKCS6.ExtendedCertificate	>().Factory(), Cast.N, Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<PKIX.AttributeCertificateV1	>().Factory(), Cast.N, Tag.Context(1)	),  
			new ObjectInfo(new ObjectCreator<PKIX.AttributeCertificate		>().Factory(), Cast.N, Tag.Context(2)	),  
			new ObjectInfo(new ObjectCreator<OtherCertificateFormat			>().Factory(), Cast.N, Tag.Context(3)	),  
		}; 
		// конструктор
		public CertificateChoices() : base(info) {} 
	}
}

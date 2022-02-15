using System;

//	OriginatorInfo ::= SEQUENCE {
//		certs	[0] IMPLICIT CertificateSet			OPTIONAL,
//		crls	[1] IMPLICIT RevocationInfoChoices	OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	public class OriginatorInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<CertificateSet		    >().Factory(), Cast.O, Tag.Context(0)), 
			new ObjectInfo(new ObjectCreator<RevocationInfoChoices  >().Factory(), Cast.O, Tag.Context(1)), 
		}; 
		// конструктор при раскодировании
		public OriginatorInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public OriginatorInfo(CertificateSet certs, RevocationInfoChoices crls) : 
			base(info, certs, crls) {}

		public CertificateSet			Certs	{ get { return (CertificateSet			)this[0]; } } 
		public RevocationInfoChoices	Crls	{ get { return (RevocationInfoChoices	)this[1]; } }
	}
}

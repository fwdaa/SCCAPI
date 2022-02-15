using System;

//	RevokedCertificate ::= SEQUENCE  {
//		userCertificate    INTEGER,
//		revocationDate     Time,
//		crlEntryExtensions Extensions OPTIONAL
//	} 

namespace Aladdin.ASN1.ISO.PKIX
{
	public class RevokedCertificate : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer	>().Factory(), Cast.N), 
			new ObjectInfo(new ChoiceCreator<Time		>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Extensions	>().Factory(), Cast.O), 
		}; 
		// конструктор при раскодировании
		public RevokedCertificate(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public RevokedCertificate(Integer userCertificate, 
			VisibleString revocationDate, Extensions crlEntryExtensions) : 
			base(info, userCertificate, revocationDate, crlEntryExtensions) {} 

		public Integer			UserCertificate		{ get { return (Integer			)this[0]; } } 
		public VisibleString	RevocationDate		{ get { return (VisibleString	)this[1]; } }
		public Extensions		CRLEntryExtensions  { get { return (Extensions		)this[2]; } }
	}
}

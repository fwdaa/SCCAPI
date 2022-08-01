using System;
using System.Runtime.Serialization;

// RevokedInfo ::= SEQUENCE {
//    revocationTime                GeneralizedTime,
//    revocationReason [0] EXPLICIT CRLReason OPTIONAL
// }

namespace Aladdin.ASN1.ISO.OCSP
{
	[Serializable]
	public class RevokedInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<GeneralizedTime              >().Factory(), Cast.N                 ), 
			new ObjectInfo(new ObjectCreator<Enumerated<PKIX.CE.CrlReason>>().Factory(), Cast.EO, Tag.Context(0)) 
		}; 
		// конструктор при сериализации
        protected RevokedInfo(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public RevokedInfo(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public RevokedInfo(GeneralizedTime revocationTime, Enumerated<PKIX.CE.CrlReason> revocationReason) : 
			base(info, revocationTime, revocationReason) {} 

		public GeneralizedTime					RevocationTime		{ get { return (GeneralizedTime					)this[0]; } } 
		public Enumerated<PKIX.CE.CrlReason>	RevocationReason	{ get { return (Enumerated<PKIX.CE.CrlReason>   )this[1]; } }
	}
}

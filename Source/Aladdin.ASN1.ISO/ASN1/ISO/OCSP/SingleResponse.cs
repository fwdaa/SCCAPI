using System;
using System.Runtime.Serialization;

// SingleResponse ::= SEQUENCE {
//      certID                        CertID,
//      certStatus                    CertStatus,
//      thisUpdate                    GeneralizedTime,
//      nextUpdate       [0] EXPLICIT GeneralizedTime OPTIONAL,
//      singleExtensions [1] EXPLICIT Extensions {{re-ocsp-crl | re-ocsp-archive-cutoff | CrlEntryExtensions, ...}} OPTIONAL
// }

namespace Aladdin.ASN1.ISO.OCSP
{
	[Serializable]
	public class SingleResponse : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<CertID         >().Factory(), Cast.N					), 
			new ObjectInfo(new ChoiceCreator<CertStatus     >().Factory(), Cast.N					), 
			new ObjectInfo(new ObjectCreator<GeneralizedTime>().Factory(), Cast.N					),  
			new ObjectInfo(new ObjectCreator<GeneralizedTime>().Factory(), Cast.EO, Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<PKIX.Extensions>().Factory(), Cast.EO, Tag.Context(1)	) 
		}; 
		// конструктор при сериализации
        protected SingleResponse(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public SingleResponse(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public SingleResponse(CertID certID, IEncodable certStatus, GeneralizedTime thisUpdate, 
			GeneralizedTime nextUpdate, PKIX.Extensions singleExtensions) : 
			base(info, certID, certStatus, thisUpdate, nextUpdate, singleExtensions) {} 

		public CertID			CertID				{ get { return (CertID			)this[0]; } } 
		public IEncodable		CertStatus			{ get { return (IEncodable      )this[1]; } }
		public GeneralizedTime	ThisUpdate			{ get { return (GeneralizedTime	)this[2]; } }
		public GeneralizedTime	NextUpdate			{ get { return (GeneralizedTime	)this[3]; } }
		public PKIX.Extensions	SingleExtensions	{ get { return (PKIX.Extensions	)this[4]; } }
	}
}

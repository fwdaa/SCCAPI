using System;
using System.Runtime.Serialization;

// TBSRequest ::= SEQUENCE {
//     version           [0] EXPLICIT INTEGER DEFAULT v1(0),
//     requestorName     [1] EXPLICIT GeneralName OPTIONAL,
//     requestList           SEQUENCE OF Request,
//     requestExtensions [2] EXPLICIT Extensions {{re-ocsp-nonce | re-ocsp-response, ..., re-ocsp-preferred-signature-algorithms}} OPTIONAL
//  }

namespace Aladdin.ASN1.ISO.OCSP
{
	[Serializable]
	public class TBSRequest : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer          >().Factory(), Cast.E,  Tag.Context(0), new Integer(0)), 
			new ObjectInfo(new ChoiceCreator<PKIX.GeneralName >().Factory(), Cast.EO, Tag.Context(1)                ), 
			new ObjectInfo(new ObjectCreator<Sequence<Request>>().Factory(), Cast.N								    ), 
			new ObjectInfo(new ObjectCreator<PKIX.Extensions  >().Factory(), Cast.EO, Tag.Context(2)			    ) 
		}; 
		// конструктор при сериализации
        protected TBSRequest(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public TBSRequest(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public TBSRequest(Integer version, IEncodable requestorName, 
			Sequence<Request> requestList, PKIX.Extensions requestExtensions) : 
			base(info, version, requestorName, requestList, requestExtensions) {} 

		public Integer				Version				{ get { return (Integer				)this[0]; } } 
		public IEncodable			RequestorName		{ get { return (IEncodable			)this[1]; } }
		public Sequence<Request>	RequestList			{ get { return (Sequence<Request>	)this[2]; } }
		public PKIX.Extensions		RequestExtensions	{ get { return (PKIX.Extensions		)this[3]; } }
	}
}

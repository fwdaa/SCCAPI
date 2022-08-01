using System;
using System.Runtime.Serialization;

// ResponseData ::= SEQUENCE {
//		version              [0] EXPLICIT INTEGER DEFAULT v1(0),
//      responderID				 ResponderID,
//      producedAt               GeneralizedTime,
//      responses                SEQUENCE OF SingleResponse,
//      responseExtensions   [1] EXPLICIT Extensions {{re-ocsp-nonce, ..., re-ocsp-extended-revoke}} OPTIONAL
// }

namespace Aladdin.ASN1.ISO.OCSP
{
	[Serializable]
	public class ResponseData : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer                 >().Factory(), Cast.E,  Tag.Any, new Integer(0)), 
			new ObjectInfo(new ChoiceCreator<ResponderID             >().Factory(), Cast.N,  Tag.Any                ), 
			new ObjectInfo(new ObjectCreator<GeneralizedTime         >().Factory(), Cast.N,  Tag.Any                ), 
			new ObjectInfo(new ObjectCreator<Sequence<SingleResponse>>().Factory(), Cast.N,  Tag.Any                ),
			new ObjectInfo(new ObjectCreator<PKIX.Extensions         >().Factory(), Cast.EO, Tag.Context(0)         ) 
		}; 
		// конструктор при сериализации
        protected ResponseData(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public ResponseData(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public ResponseData(Integer version, IEncodable responderID, GeneralizedTime producedAt, 
			Sequence<SingleResponse> responses, PKIX.Extensions responseExtensions) : 
			base(info, version, responderID, producedAt, responses, responseExtensions) {} 

		public Integer						Version				{ get { return (Integer					)this[0]; } } 
		public IEncodable					ResponderID			{ get { return (IEncodable				)this[1]; } }
		public GeneralizedTime				ProducedAt			{ get { return (GeneralizedTime			)this[2]; } }
		public Sequence<SingleResponse>		Responses			{ get { return (Sequence<SingleResponse>)this[3]; } }
		public PKIX.Extensions				ResponseExtensions	{ get { return (PKIX.Extensions			)this[4]; } }
	}
}

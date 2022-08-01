using System;
using System.Runtime.Serialization;

// OCSPRequest ::= SEQUENCE {
//     tbsRequest        TBSRequest,
//     optionalSignature [0] EXPLICIT Signature OPTIONAL
// }

namespace Aladdin.ASN1.ISO.OCSP
{
	[Serializable]
	public class OCSPRequest : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<TBSRequest>().Factory(), Cast.N                 ), 
			new ObjectInfo(new ObjectCreator<Signature >().Factory(), Cast.EO, Tag.Context(0)) 
		}; 
		// конструктор при сериализации
        protected OCSPRequest(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public OCSPRequest(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public OCSPRequest(TBSRequest tbsRequest, Signature optionalSignature) : 
			base(info, tbsRequest, optionalSignature) {} 

		public TBSRequest	TBSRequest			{ get { return (TBSRequest	)this[0]; } } 
		public Signature	OptionalSignature	{ get { return (Signature	)this[1]; } }
	}
}

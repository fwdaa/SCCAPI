using System;
using System.Runtime.Serialization;

// OCSPResponse ::= SEQUENCE {
//    responseStatus              OCSPResponseStatus,
//    responseBytes  [0] EXPLICIT ResponseBytes OPTIONAL
// }

namespace Aladdin.ASN1.ISO.OCSP
{
	[Serializable]
	public class OCSPResponse : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Enumerated<OCSPResponseStatus>>().Factory(), Cast.N                 ), 
			new ObjectInfo(new ObjectCreator<ResponseBytes			       >().Factory(), Cast.EO, Tag.Context(0)) 
		}; 
		// конструктор при сериализации
        protected OCSPResponse(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public OCSPResponse(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public OCSPResponse(Enumerated<OCSPResponseStatus> responseStatus, ResponseBytes ResponseBytes) : 
			base(info, responseStatus, ResponseBytes) {} 

		public Enumerated<OCSPResponseStatus>	ResponseStatus	{ get { return (Enumerated<OCSPResponseStatus>)this[0]; } } 
		public ResponseBytes					ResponseBytes	{ get { return (ResponseBytes                 )this[1]; } }
	}
}

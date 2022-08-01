using System;
using System.Runtime.Serialization;

// Request ::= SEQUENCE {
//     reqCert                              CertID,
//     singleRequestExtensions [0] EXPLICIT Extensions { {re-ocsp-service-locator, ...}} OPTIONAL
// }

namespace Aladdin.ASN1.ISO.OCSP
{
	[Serializable]
	public class Request : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<CertID         >().Factory(), Cast.N                 ), 
			new ObjectInfo(new ObjectCreator<PKIX.Extensions>().Factory(), Cast.EO, Tag.Context(0)), 
		}; 
		// конструктор при сериализации
        protected Request(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public Request(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public Request(CertID reqCert, PKIX.Extensions singleRequestExtensions) : 
			base(info, reqCert, singleRequestExtensions) {} 

		public CertID			ReqCert					{ get { return (CertID			)this[0]; } } 
		public PKIX.Extensions	SingleRequestExtensions	{ get { return (PKIX.Extensions )this[1]; } }
	}
}

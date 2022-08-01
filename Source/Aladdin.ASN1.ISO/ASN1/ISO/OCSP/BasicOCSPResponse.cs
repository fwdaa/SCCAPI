using System;
using System.Runtime.Serialization;

// BasicOCSPResponse ::= SEQUENCE {
//		tbsResponseData         ResponseData,
//		signatureAlgorithm      AlgorithmIdentifier {SIGNATURE-ALGORITHM, {sa-dsaWithSHA1 | sa-rsaWithSHA1 | sa-rsaWithMD5 | sa-rsaWithMD2, ...}},
//		signature               BIT STRING,
//		certs				[0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
// }

namespace Aladdin.ASN1.ISO.OCSP
{
	[Serializable]
	public class BasicOCSPResponse : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ResponseData              >().Factory(), Cast.N,  Tag.Any       ), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier       >().Factory(), Cast.N,  Tag.Any       ), 
			new ObjectInfo(new ObjectCreator<BitString                 >().Factory(), Cast.N,  Tag.Any       ), 
			new ObjectInfo(new ObjectCreator<Sequence<PKIX.Certificate>>().Factory(), Cast.EO, Tag.Context(0))
		}; 
		// конструктор при сериализации
        protected BasicOCSPResponse(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public BasicOCSPResponse(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public BasicOCSPResponse(ResponseData tbsResponseData, 
			AlgorithmIdentifier signatureAlgorithm, BitString signature, Sequence<PKIX.Certificate> certs) : 
			base(info, tbsResponseData, signatureAlgorithm, signature, certs) {} 

		public ResponseData					TBSResponseData		{ get { return (ResponseData					)this[0]; } } 
		public AlgorithmIdentifier			SignatureAlgorithm	{ get { return (AlgorithmIdentifier				)this[1]; } }
		public BitString					Signature			{ get { return (BitString						)this[2]; } }
		public Sequence<SingleResponse>		Responses			{ get { return (Sequence<SingleResponse>		)this[3]; } }
		public Sequence<PKIX.Certificate>	Certs				{ get { return (Sequence<PKIX.Certificate>		)this[4]; } }
	}
}

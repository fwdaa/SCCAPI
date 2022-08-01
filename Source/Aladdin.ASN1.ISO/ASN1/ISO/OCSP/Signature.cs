using System;
using System.Runtime.Serialization;

// Signature ::= SEQUENCE {
//    signatureAlgorithm AlgorithmIdentifier { SIGNATURE-ALGORITHM, {...}},
//    signature          BIT STRING,
//    certs              [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
// }

namespace Aladdin.ASN1.ISO.OCSP
{
	[Serializable]
	public class Signature : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier       >().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<BitString				   >().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Sequence<PKIX.Certificate>>().Factory(), Cast.EO, Tag.Context(0)) 
		}; 
		// конструктор при сериализации
        protected Signature(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public Signature(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public Signature(AlgorithmIdentifier signatureAlgorithm, 
			BitString signature, Sequence<PKIX.Certificate> certificates) : 
			base(info, signatureAlgorithm, signature, certificates) {} 

		public AlgorithmIdentifier			SignatureAlgorithm	{ get { return (AlgorithmIdentifier			)this[0]; } } 
		public BitString					SignatureValue		{ get { return (BitString					)this[1]; } }
		public Sequence<PKIX.Certificate>	Certs				{ get { return (Sequence<PKIX.Certificate>	)this[2]; } }
	}
}

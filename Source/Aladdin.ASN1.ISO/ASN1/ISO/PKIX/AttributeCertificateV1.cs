using System;
using System.Runtime.Serialization;

//	AttributeCertificateV1 ::= SEQUENCE {
//		acinfo               AttributeCertificateInfoV1,
//		signatureAlgorithm   AlgorithmIdentifier,
//		signatureValue       BIT STRING
//	}

namespace Aladdin.ASN1.ISO.PKIX
{
	[Serializable]
	public class AttributeCertificateV1 : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<AttributeCertificateInfoV1	>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier		>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<BitString					>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected AttributeCertificateV1(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public AttributeCertificateV1(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public AttributeCertificateV1(AttributeCertificateInfoV1 acinfo, 
			AlgorithmIdentifier signatureAlgorithm, BitString signatureValue) : 
			base(info, acinfo, signatureAlgorithm, signatureValue) {} 

		public AttributeCertificateInfoV1	ACInfo				{ get { return (AttributeCertificateInfoV1	)this[0]; } } 
		public AlgorithmIdentifier			SignatureAlgorithm  { get { return (AlgorithmIdentifier			)this[1]; } }
		public BitString					SignatureValue		{ get { return (BitString					)this[2]; } }
	}
}

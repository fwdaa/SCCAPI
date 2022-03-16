using System;
using System.Runtime.Serialization;

//	ExtendedCertificate ::= SEQUENCE {
//		extendedCertificateInfo ExtendedCertificateInfo,
//		signatureAlgorithm		AlgorithmIdentifier,
//		signature				BIT STRING
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS6
{
	[Serializable]
	public class ExtendedCertificate : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ExtendedCertificateInfo>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier	>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<BitString				>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected ExtendedCertificate(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public ExtendedCertificate(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public ExtendedCertificate(ExtendedCertificateInfo extendedCertificateInfo, 
			AlgorithmIdentifier signatureAlgorithm, BitString signature) : 
			base(info, extendedCertificateInfo, signatureAlgorithm, signature) {}

		public ExtendedCertificateInfo	ExtendedCertificateInfo { get { return (ExtendedCertificateInfo	)this[0]; } } 
		public AlgorithmIdentifier		SignatureAlgorithm		{ get { return (AlgorithmIdentifier		)this[1]; } }
		public BitString 				Signature				{ get { return (BitString 				)this[2]; } }
	}
}

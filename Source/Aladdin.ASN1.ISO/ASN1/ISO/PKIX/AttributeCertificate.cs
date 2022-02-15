using System;

//	AttributeCertificate ::= SEQUENCE {
//		acinfo               AttributeCertificateInfo,
//		signatureAlgorithm   AlgorithmIdentifier,
//		signatureValue       BIT STRING
//	}

namespace Aladdin.ASN1.ISO.PKIX
{
	public class AttributeCertificate : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<AttributeCertificateInfo	>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier		>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<BitString				    >().Factory(), Cast.N), 
		}; 
		// конструктор при раскодировании
		public AttributeCertificate(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public AttributeCertificate(AttributeCertificateInfo acinfo, 
			AlgorithmIdentifier signatureAlgorithm, BitString signatureValue) : 
			base(info, acinfo, signatureAlgorithm, signatureValue) {} 

		public AttributeCertificateInfo	ACInfo				{ get { return (AttributeCertificateInfo)this[0]; } } 
		public AlgorithmIdentifier		SignatureAlgorithm  { get { return (AlgorithmIdentifier		)this[1]; } }
		public BitString				SignatureValue		{ get { return (BitString				)this[2]; } }
	}
}

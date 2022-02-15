using System;

//	CertificationRequest ::= SEQUENCE {
//		certificationRequestInfo	CertificationRequestInfo,
//		signatureAlgorithm			AlgorithmIdentifier,
//		signature					BIT STRING
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS10
{
	public class CertificationRequest : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<CertificationRequestInfo>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier	 >().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<BitString				 >().Factory(), Cast.N), 
		}; 
		// конструктор при раскодировании
		public CertificationRequest(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public CertificationRequest(CertificationRequestInfo certificationRequestInfo, 
			AlgorithmIdentifier signatureAlgorithm, BitString signature) : 
			base(info, certificationRequestInfo, signatureAlgorithm, signature) {}

		public CertificationRequestInfo CertificationRequestInfo	{ get { return (CertificationRequestInfo)this[0]; } } 
		public AlgorithmIdentifier		SignatureAlgorithm			{ get { return (AlgorithmIdentifier		)this[1]; } } 
		public BitString				Signature					{ get { return (BitString				)this[2]; } } 
	}
}

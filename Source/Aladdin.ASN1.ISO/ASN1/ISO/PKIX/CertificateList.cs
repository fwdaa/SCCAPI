using System;

//	CertificateList  ::=  SEQUENCE  {
//		tbsCertList          TBSCertList,
//		signatureAlgorithm   AlgorithmIdentifier,
//		signature            BIT STRING   
//	}

namespace Aladdin.ASN1.ISO.PKIX
{
	public class CertificateList : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<TBSCertList		>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<BitString			>().Factory(), Cast.N), 
		}; 
		// конструктор при раскодировании
		public CertificateList(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public CertificateList(TBSCertList tbsCertList, AlgorithmIdentifier signatureAlgorithm, 
			BitString signature) : base(info, tbsCertList, signatureAlgorithm, signature) {}

		public TBSCertList			TBSCertList			{ get { return (TBSCertList			)this[0]; } } 
		public AlgorithmIdentifier	SignatureAlgorithm  { get { return (AlgorithmIdentifier	)this[1]; } }
		public BitString			Signature			{ get { return (BitString			)this[2]; } }
	}
}

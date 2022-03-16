using System;
using System.Runtime.Serialization;

//	Certificate  ::=  SEQUENCE  {
//		tbsCertificate       TBSCertificate,
//		signatureAlgorithm   AlgorithmIdentifier,
//		signature            BIT STRING  
//	}

namespace Aladdin.ASN1.ISO.PKIX
{
	[Serializable]
	public class Certificate : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<TBSCertificate		>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<BitString			>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected Certificate(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public Certificate(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public Certificate(TBSCertificate tbsCertificate, 
			AlgorithmIdentifier signatureAlgorithm, BitString signature) : 
			base(info, tbsCertificate, signatureAlgorithm, signature) {} 

		public TBSCertificate		TBSCertificate		{ get { return (TBSCertificate		)this[0]; } } 
		public AlgorithmIdentifier	SignatureAlgorithm  { get { return (AlgorithmIdentifier	)this[1]; } }
		public BitString			Signature			{ get { return (BitString			)this[2]; } }
	}
}

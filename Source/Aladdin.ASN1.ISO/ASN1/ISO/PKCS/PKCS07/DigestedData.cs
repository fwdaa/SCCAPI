using System;

//	DigestedData ::= SEQUENCE {
//		version				INTEGER,
//		digestAlgorithm		AlgorithmIdentifier,
//		encapContentInfo	EncapsulatedContentInfo,
//		digest				OCTET STRING 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	public class DigestedData : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer				>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier	>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<EncapsulatedContentInfo>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<OctetString			>().Factory(), Cast.N), 
		}; 
		// конструктор при раскодировании
		public DigestedData(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public DigestedData(Integer version, AlgorithmIdentifier digestAlgorithm, 
			EncapsulatedContentInfo encapContentInfo, OctetString digest) : 
			base(info, version, digestAlgorithm, encapContentInfo, digest) {}

		public Integer						Version				{ get { return (Integer					)this[0]; } } 
		public AlgorithmIdentifier			DigestAlgorithm		{ get { return (AlgorithmIdentifier		)this[1]; } }
		public EncapsulatedContentInfo		EncapContentInfo	{ get { return (EncapsulatedContentInfo	)this[2]; } } 
		public OctetString					Digest				{ get { return (OctetString				)this[3]; } }
	}
}

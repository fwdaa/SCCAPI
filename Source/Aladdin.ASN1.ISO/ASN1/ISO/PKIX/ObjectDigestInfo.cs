using System;

//	ObjectDigestInfo    ::= SEQUENCE {
//		digestedObjectType  INTEGER,
//		otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
//		digestAlgorithm     AlgorithmIdentifier,
//		objectDigest        BIT STRING
//	}

namespace Aladdin.ASN1.ISO.PKIX
{
	public class ObjectDigestInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<ObjectIdentifier	>().Factory(), Cast.O), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<BitString			>().Factory(), Cast.N), 
		}; 
		// конструктор при раскодировании
		public ObjectDigestInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public ObjectDigestInfo(Integer digestedObjectType, 
			ObjectIdentifier otherObjectTypeID, AlgorithmIdentifier digestAlgorithm, 
			BitString objectDigest) : base(info, digestedObjectType, 
			otherObjectTypeID, digestAlgorithm, objectDigest) {}

		public Integer				DigestedObjectType	{ get { return (Integer				)this[0]; } } 
		public ObjectIdentifier		OtherObjectTypeID	{ get { return (ObjectIdentifier	)this[1]; } }
		public AlgorithmIdentifier	DigestAlgorithm		{ get { return (AlgorithmIdentifier	)this[2]; } } 
		public BitString			ObjectDigest		{ get { return (BitString			)this[3]; } }
	}
}

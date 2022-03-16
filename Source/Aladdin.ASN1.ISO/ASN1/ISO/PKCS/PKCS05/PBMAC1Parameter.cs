using System;
using System.Runtime.Serialization;

//	PBMAC1Parameter ::= SEQUENCE {
//		keyDerivationFunc	AlgorithmIdentifier,
//		messageAuthScheme	AlgorithmIdentifier
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS5
{
	[Serializable]
	public class PBMAC1Parameter : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected PBMAC1Parameter(SerializationInfo info, StreamingContext context) : base(info, context) {}
		// конструктор при раскодировании
		public PBMAC1Parameter(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public PBMAC1Parameter(AlgorithmIdentifier keyDerivationFunc, 
			AlgorithmIdentifier messageAuthScheme) : base(info, keyDerivationFunc, messageAuthScheme) {}

		public AlgorithmIdentifier	KeyDerivationFunc	{ get { return (AlgorithmIdentifier)this[0]; } }
		public AlgorithmIdentifier	MessageAuthScheme	{ get { return (AlgorithmIdentifier)this[1]; } }
	}
}

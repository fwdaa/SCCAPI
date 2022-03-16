using System;
using System.Runtime.Serialization;

//	PBES2Parameter ::= SEQUENCE {
//		keyDerivationFunc	AlgorithmIdentifier,
//		encryptionScheme	AlgorithmIdentifier
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS5
{
	[Serializable]
	public class PBES2Parameter : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected PBES2Parameter(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public PBES2Parameter(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public PBES2Parameter(AlgorithmIdentifier keyDerivationFunc, 
			AlgorithmIdentifier encryptionScheme) : 
			base(info, keyDerivationFunc, encryptionScheme) {}

		public AlgorithmIdentifier	KeyDerivationFunc	{ get { return (AlgorithmIdentifier)this[0]; } }
		public AlgorithmIdentifier	EncryptionScheme	{ get { return (AlgorithmIdentifier)this[1]; } }
	}
}

using System;
using System.Runtime.Serialization;

//	PBKDF2Parameter ::= SEQUENCE {
//		salt			PBSalt,
//		iterationCount	INTEGER (1..MAX),
//		keyLength		INTEGER (1..MAX)	OPTIONAL,
//		prf				AlgorithmIdentifier DEFAULT hmac_sha1
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS5
{
	[Serializable]
	public class PBKDF2Parameter : Sequence
	{
		// значение псевдослучайной функции по умолчанию
		private static readonly AlgorithmIdentifier prf = 
			new AlgorithmIdentifier(new ObjectIdentifier("1.2.840.113549.2.7"), Null.Instance);  

		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ChoiceCreator<PBSalt				>().Factory( ), Cast.N,	Tag.Any		), 
			new ObjectInfo(new ObjectCreator<Integer			>().Factory(1), Cast.N,	Tag.Any		), 
			new ObjectInfo(new ObjectCreator<Integer			>().Factory(1), Cast.O,	Tag.Any		), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory( ), Cast.O,	Tag.Any, prf), 
		}; 
		// конструктор при сериализации
        protected PBKDF2Parameter(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public PBKDF2Parameter(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public PBKDF2Parameter(IEncodable salt, Integer iterationCount, Integer keyLength, 
			AlgorithmIdentifier prf) : base(info, salt, iterationCount, keyLength, prf) {}

		public IEncodable			Salt			{ get { return						 this[0]; } }
		public Integer				IterationCount	{ get { return (Integer				)this[1]; } }
		public Integer				KeyLength		{ get { return (Integer				)this[2]; } }
		public AlgorithmIdentifier	PRF				{ get { return (AlgorithmIdentifier	)this[3]; } }
	}
}

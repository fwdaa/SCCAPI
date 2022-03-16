using System;
using System.Runtime.Serialization;

// PrivateKeyInfo ::= SEQUENCE {
//		version								INTEGER,
//		privateKeyAlgorithm					AlgorithmIdentifier,
//		privateKey							OCTET STRING,
//		attributes			[0] IMPLICIT	Attributes		OPTIONAL
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS8
{
	[Serializable]
	public class PrivateKeyInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer			>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<OctetString		>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<Attributes			>().Factory(), Cast.O,	Tag.Context(0)	), 
		}; 
		// конструктор при сериализации
        protected PrivateKeyInfo(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public PrivateKeyInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public PrivateKeyInfo(Integer version, AlgorithmIdentifier privateKeyAlgorithm, 
			OctetString privateKey, Attributes attributes) : 
			base(info, version, privateKeyAlgorithm, privateKey, attributes) {}

		public Integer				Version				{ get { return (Integer				)this[0]; } } 
		public AlgorithmIdentifier	PrivateKeyAlgorithm	{ get { return (AlgorithmIdentifier	)this[1]; } }
		public OctetString			PrivateKey			{ get { return (OctetString			)this[2]; } } 
		public Attributes			Attributes			{ get { return (Attributes			)this[3]; } }
	}
}

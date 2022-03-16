﻿using System;
using System.Runtime.Serialization;

//	DigestInfo ::= SEQUENCE {
//		digestAlgorithm AlgorithmIdentifier,
//		digest          OCTET STRING
//	}

namespace Aladdin.ASN1.ISO.PKCS
{
	[Serializable]
	public class DigestInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<OctetString		>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected DigestInfo(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public DigestInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public DigestInfo(AlgorithmIdentifier digestAlgorithm, OctetString digest) : 
			base(info, digestAlgorithm, digest) {}

		public AlgorithmIdentifier	DigestAlgorithm	{ get { return (AlgorithmIdentifier	)this[0]; } }
		public OctetString			Digest			{ get { return (OctetString			)this[1]; } }
	}
}

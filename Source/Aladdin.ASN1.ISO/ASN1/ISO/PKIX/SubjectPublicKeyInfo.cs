﻿using System;

//	SubjectPublicKeyInfo  ::=  SEQUENCE  {
//		algorithm            AlgorithmIdentifier,
//		subjectPublicKey     BIT STRING  
//	}

namespace Aladdin.ASN1.ISO.PKIX
{
	public class SubjectPublicKeyInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<BitString			>().Factory(), Cast.N), 
		}; 
		// конструктор при раскодировании
		public SubjectPublicKeyInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public SubjectPublicKeyInfo(AlgorithmIdentifier algorithm, BitString subjectPublicKey) : 
			base(info, algorithm, subjectPublicKey) {}

		public AlgorithmIdentifier Algorithm		{ get { return (AlgorithmIdentifier	)this[0]; } } 
		public BitString		   SubjectPublicKey	{ get { return (BitString			)this[1]; } }
	}
}
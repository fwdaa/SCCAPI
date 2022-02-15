using System;
using Aladdin.ASN1.ISO;

//	GOSTRPrivateKeyParameters ::= SEQUENCE {
//		attributes			GostPrivateKeyAttributes,
//		privateKeyAlgorithm	[0] IMPLICIT AlgorithmIdentifier
//	}
//  GostPrivateKeyAttributes ::= BIT STRING {
//      pkaExportable(0), pkaUserProtect(1), pkaExchange(2), pkaEphemeral(3), pkaNonCachable(4)
//  }

namespace Aladdin.ASN1.GOST
{
	public class CryptoProPrivateKeyParameters : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<BitString			>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N,	Tag.Context(0)	), 
		}; 
		// конструктор при раскодировании
		public CryptoProPrivateKeyParameters(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public CryptoProPrivateKeyParameters(BitString attributes, AlgorithmIdentifier privateKeyAlgorithm) : 
			base(info, attributes, privateKeyAlgorithm) {}

		public BitString			Attributes			{ get { return (BitString			)this[0]; } } 
		public AlgorithmIdentifier	PrivateKeyAlgorithm	{ get { return (AlgorithmIdentifier	)this[1]; } }
	}
}

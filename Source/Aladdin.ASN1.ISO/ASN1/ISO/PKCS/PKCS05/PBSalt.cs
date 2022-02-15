using System;

//	SaltParameter ::= CHOICE {
//		specified	OCTET STRING,
//		otherSource AlgorithmIdentifier 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS5
{
	public class PBSalt : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString		>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<AlgorithmIdentifier>().Factory(), Cast.N), 
		}; 
		// конструктор
		public PBSalt() : base(info) {} 
	}
}

using System;
using System.Runtime.Serialization;

//	RSAPublicKey ::= SEQUENCE {
//		modulus			INTEGER,
//		publicExponent	INTEGER
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS1
{
	[Serializable]
	public class RSAPublicKey : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected RSAPublicKey(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public RSAPublicKey(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public RSAPublicKey(Integer modulus, Integer publicExponent) : 
			base(info, modulus, publicExponent) {}

		public Integer Modulus			{ get { return (Integer)this[0]; } } 
		public Integer PublicExponent	{ get { return (Integer)this[1]; } }
	}
}

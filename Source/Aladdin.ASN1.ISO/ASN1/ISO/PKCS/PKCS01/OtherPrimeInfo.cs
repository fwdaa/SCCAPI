using System;
using System.Runtime.Serialization;

//	OtherPrimeInfo ::= SEQUENCE {
//		prime		INTEGER, 
//		exponent	INTEGER, 
//		coefficient INTEGER 
//}
namespace Aladdin.ASN1.ISO.PKCS.PKCS1
{
	[Serializable]
	public class OtherPrimeInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected OtherPrimeInfo(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public OtherPrimeInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public OtherPrimeInfo(Integer prime, Integer exponent, Integer coefficient) : 
			base(info, prime, exponent, coefficient) {}

		public Integer Prime		{ get { return (Integer)this[0]; } } 
		public Integer Exponent		{ get { return (Integer)this[1]; } }
		public Integer Coefficient	{ get { return (Integer)this[2]; } }
	}
}

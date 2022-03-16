using System;
using System.Runtime.Serialization;

//	E163-4-address ::= SEQUENCE {
//		number      [0] IMPLICIT NumericString (SIZE (1..ub-e163-4-number-length)),
//		sub-address [1] IMPLICIT NumericString (SIZE (1..ub-e163-4-sub-address-length)) OPTIONAL 
//	}
//	ub-e163-4-number-length			INTEGER ::= 15
//	ub-e163-4-sub-address-length	INTEGER ::= 40

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	[Serializable]
	public class E1634Address : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<NumericString>().Factory(1, 15), Cast.N, Tag.Context(0)), 
			new ObjectInfo(new ObjectCreator<NumericString>().Factory(1, 40), Cast.O, Tag.Context(1)), 
		}; 
		// конструктор при сериализации
        protected E1634Address(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public E1634Address(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public E1634Address(NumericString number, NumericString subAddress) : 
			base(info, number, subAddress) {}

		public NumericString Number		{ get { return (NumericString)this[0]; } }
		public NumericString SubAddress	{ get { return (NumericString)this[1]; } }
	}
}

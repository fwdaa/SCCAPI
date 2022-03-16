using System;
using System.Runtime.Serialization;

//	AttributeValidity  ::= SEQUENCE {
//		notBeforeTime  GeneralizedTime,
//		notAfterTime   GeneralizedTime
//	}

namespace Aladdin.ASN1.ISO.PKIX
{
	[Serializable]
	public class AttributeValidity : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<GeneralizedTime>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<GeneralizedTime>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected AttributeValidity(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public AttributeValidity(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public AttributeValidity(GeneralizedTime notBeforeTime, GeneralizedTime notAfterTime) : 
			base(info, notBeforeTime, notAfterTime) {}

		public GeneralizedTime NotBeforeTime { get { return (GeneralizedTime)this[0]; } } 
		public GeneralizedTime NotAfterTime  { get { return (GeneralizedTime)this[1]; } }
	}
}

using System;
using System.Runtime.Serialization;

//	FBParameter ::= SEQUENCE {
//		iv				OCTET STRING,
//		numberOfBits	INTEGER
//	}

namespace Aladdin.ASN1.ANSI
{
	[Serializable]
	public class FBParameter : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer	>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected FBParameter(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public FBParameter(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public FBParameter(OctetString iv, Integer numberOfBits) : 
			base(info, iv, numberOfBits) {}
		
		public OctetString	IV				{ get { return (OctetString	)this[0]; } }
		public Integer		NumberOfBits	{ get { return (Integer		)this[1]; } }
	}
}

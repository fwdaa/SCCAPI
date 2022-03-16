using System;
using System.Runtime.Serialization;

//	PBEParameter ::= SEQUENCE {
//		salt			OCTET STRING,
//		iterationCount	INTEGER
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS5
{
	[Serializable]
	public class PBEParameter : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<Integer	>().Factory(), Cast.N), 
		}; 
		// конструктор при сериализации
        protected PBEParameter(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public PBEParameter(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public PBEParameter(OctetString salt, Integer iterationCount) : 
			base(info, salt, iterationCount) {}

		public OctetString	Salt			{ get { return (OctetString)this[0]; } }
		public Integer		IterationCount	{ get { return (Integer	   )this[1]; } }
	}
}

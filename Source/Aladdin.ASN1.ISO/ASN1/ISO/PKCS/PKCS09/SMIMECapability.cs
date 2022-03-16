using System;
using System.Runtime.Serialization;

//	SMIMECapability  ::=  SEQUENCE  {
//		algorithm  OBJECT IDENTIFIER,
//		parameters ANY DEFINED BY algorithm
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS9
{
	[Serializable]
	public class SMIMECapability : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(    ImplicitCreator				    .Factory  , Cast.N), 
		}; 
		// конструктор при сериализации
        protected SMIMECapability(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public SMIMECapability(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public SMIMECapability(ObjectIdentifier algorithm, IEncodable parameters) : 
			base(info, algorithm, parameters) {}

		public ObjectIdentifier	Algorithm	{ get { return (ObjectIdentifier)this[0]; } } 
		public IEncodable		Parameters	{ get { return                   this[1]; } }
	}
}

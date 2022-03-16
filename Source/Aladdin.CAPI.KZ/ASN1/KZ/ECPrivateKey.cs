using System; 
using System.Runtime.Serialization;

//	ECPrivateKey ::= SEQUENCE {
//      version            INTEGER (1), 
//		value              OCTET STRING (SIZE (32))
//	}

namespace Aladdin.ASN1.KZ
{
	[Serializable]
    public class ECPrivateKey  : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer	>().Factory(      ), Cast.N, Tag.Any), 
			new ObjectInfo(new ObjectCreator<OctetString>().Factory(32, 32), Cast.N, Tag.Any), 
		}; 
		// конструктор при сериализации
        protected ECPrivateKey(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public ECPrivateKey(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public ECPrivateKey(Integer version, OctetString value) : base(info, version, value) {}  

		public Integer		Version	{ get { return (Integer		)this[0]; } } 
		public OctetString	Value	{ get { return (OctetString	)this[1]; } } 
	}
}

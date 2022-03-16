using System;
using System.Runtime.Serialization; 

//	GOST28147KeyWrapParameters ::= SEQUENCE {
//		encryptionParamSet OBJECT IDENTIFIER,
//		ukm                OCTET STRING (SIZE (8..16)) OPTIONAL
//	}

namespace Aladdin.ASN1.GOST
{
    [Serializable]
	public class KeyWrapParameters : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier	>().Factory(     ), Cast.N), 
			new ObjectInfo(new ObjectCreator<OctetString		>().Factory(8, 16), Cast.O), 
		}; 
		// конструктор при сериализации
        protected KeyWrapParameters(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public KeyWrapParameters(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public KeyWrapParameters(ObjectIdentifier encryptionParamSet, OctetString ukm) : 
			base(info, encryptionParamSet, ukm) {}  

		public ObjectIdentifier	ParamSet	{ get { return (ObjectIdentifier)this[0]; } }
		public OctetString		Ukm			{ get { return (OctetString		)this[1]; } } 
	}
}

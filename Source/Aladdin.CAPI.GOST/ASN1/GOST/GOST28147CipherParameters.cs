using System;
using System.Runtime.Serialization; 

//	GOST28147Parameters ::= SEQUENCE {
//		iv                   OCTET STRING (SIZE (8)),
//		encryptionParamSet   OBJECT IDENTIFIER
//	}

namespace Aladdin.ASN1.GOST
{
    [Serializable]
	public class GOST28147CipherParameters : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString		>().Factory(8, 8), Cast.N), 
			new ObjectInfo(new ObjectCreator<ObjectIdentifier	>().Factory(    ), Cast.N), 
		}; 
		// конструктор при сериализации
        protected GOST28147CipherParameters(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public GOST28147CipherParameters(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public GOST28147CipherParameters(OctetString iv, ObjectIdentifier paramSet) : 
			base(info, iv, paramSet) {}  

		public OctetString		IV			{ get { return (OctetString		)this[0]; } } 
		public ObjectIdentifier	ParamSet	{ get { return (ObjectIdentifier)this[1]; } }
	}
}

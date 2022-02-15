using System;

//	SecretBag ::= SEQUENCE {
//		secretTypeId				 OBJECT IDENTIFIER,
//		secretValue		[0] EXPLICIT ANY DEFINED BY secretTypeId
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS12
{
	public class SecretBag : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(    ImplicitCreator				    .Factory  , Cast.E,	Tag.Context(0)	), 
		}; 
		// конструктор при раскодировании
		public SecretBag(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public SecretBag(ObjectIdentifier secretTypeId, IEncodable secretValue) : 
			base(info, secretTypeId, secretValue) {}

		public ObjectIdentifier	SecretTypeId	{ get { return (ObjectIdentifier)this[0]; } } 
		public IEncodable		SecretValue		{ get { return					 this[1]; } }
	}
}

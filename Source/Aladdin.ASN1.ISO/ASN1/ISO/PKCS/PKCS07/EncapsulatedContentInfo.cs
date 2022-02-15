using System;

//	EncapsulatedContentInfo ::= SEQUENCE {
//		eContentType OBJECT IDENTIFIER,
//		eContent [0] EXPLICIT OCTET STRING OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	public class EncapsulatedContentInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier	>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(new ObjectCreator<OctetString		>().Factory(), Cast.EO,	Tag.Context(0)	), 
		}; 
		// конструктор при раскодировании
		public EncapsulatedContentInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public EncapsulatedContentInfo(ObjectIdentifier eContentType, OctetString eContent) : 
			base(info, eContentType, eContent) {}

		public ObjectIdentifier	EContentType	{ get { return (ObjectIdentifier)this[0]; } } 
		public OctetString		EContent		{ get { return (OctetString		)this[1]; } }
	}
}

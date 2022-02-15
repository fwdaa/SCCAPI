using System;

//	ContentInfo ::= SEQUENCE {
//		contentType				 OBJECT IDENTIFIER,
//		content		[0] EXPLICIT ANY DEFINED BY contentType 
//	}

namespace Aladdin.ASN1.ISO.PKCS
{
	public class ContentInfo : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(    ImplicitCreator				    .Factory  , Cast.E,	Tag.Context(0)	), 
		}; 
		// конструктор при раскодировании
		public ContentInfo(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public ContentInfo(ObjectIdentifier contentType, IEncodable content) : 
			base(info, contentType, content) {}

		public ObjectIdentifier	ContentType	{ get { return (ObjectIdentifier)this[0]; } } 
		public IEncodable		Inner		{ get { return					 this[1]; } }
	}
}

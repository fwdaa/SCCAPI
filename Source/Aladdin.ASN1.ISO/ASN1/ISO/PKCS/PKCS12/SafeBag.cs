using System;

//	SafeBag ::= SEQUENCE {
//		bagId						 OBJECT IDENTIFIER
//		bagValue		[0] EXPLICIT ANY DEFINED BY bagId,
//		bagAttributes				 Attributes				OPTIONAL
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS12
{
	public class SafeBag : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N,	Tag.Any			), 
			new ObjectInfo(    ImplicitCreator				    .Factory  , Cast.E,	Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<Attributes		 >().Factory(), Cast.O,	Tag.Any			), 
		}; 
		// конструктор при раскодировании
		public SafeBag(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public SafeBag(ObjectIdentifier bagId, IEncodable bagValue, Attributes bagAttributes) : 
			base(info, bagId, bagValue, bagAttributes) {}

		public ObjectIdentifier	BagId			{ get { return (ObjectIdentifier)this[0]; } } 
		public IEncodable		BagValue		{ get { return					 this[1]; } }
		public Attributes		BagAttributes	{ get { return (Attributes		)this[2]; } }

		///////////////////////////////////////////////////////////////////////
		// Идентификатор элемента
		///////////////////////////////////////////////////////////////////////
        public byte[] LocalKeyID { get 
        {
		    // извлечь атрибуты
			ASN1.ISO.Attributes attributes = BagAttributes; 

			// проверить наличие атрибутов
			if (attributes == null) return null; 

            // получить атрибут идентификатора
            ASN1.ISO.Attribute attribute = attributes[ASN1.ISO.PKCS.PKCS9.OID.localKeyId];

            // проверить наличие атрибута
            if (attribute == null) return null; 

	        // указать идентификатор объекта
			try { return new ASN1.OctetString(attribute.Values[0]).Value; } catch { return null; }
        }}
	}
}

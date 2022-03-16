using System;
using System.Runtime.Serialization;

//	AdministrationDomainName ::= [APPLICATION 2] EXPLICIT CHOICE {
//		numeric   NumericString   (SIZE (0..ub-domain-name-length)),
//		printable PrintableString (SIZE (0..ub-domain-name-length)) 
//	}
//	ub-domain-name-length INTEGER ::= 16

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	[Serializable]
	public class AdministrationDomainName : Explicit
	{
		// допустимые типы объекта
		public static bool IsValidTag(Tag tag) { return tag == Tag.Application(2); }

		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<NumericString  >().Factory(0, 16), Cast.N), 
			new ObjectInfo(new ObjectCreator<PrintableString>().Factory(0, 16), Cast.N), 
		}; 
		// конструктор при сериализации
        protected AdministrationDomainName(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public AdministrationDomainName(IEncodable encodable) : base(new Choice(info), encodable) {} 

		// конструктор при закодировании
		public AdministrationDomainName(OctetString value) : base(new Choice(info), Tag.Application(2), value) {}  
	}
}

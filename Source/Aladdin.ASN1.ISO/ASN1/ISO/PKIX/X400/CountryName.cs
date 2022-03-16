using System;
using System.Runtime.Serialization;

//	CountryName ::= [APPLICATION 1] EXPLICIT CHOICE {
//		x121-dcc-code			NumericString	(SIZE (ub-country-name-numeric-length)),
//		iso-3166-alpha2-code	PrintableString	(SIZE (ub-country-name-alpha-length)) 
//	}
// ub-country-name-numeric-length	INTEGER ::= 3
// ub-country-name-alpha-length		INTEGER ::= 2

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	[Serializable]
	public class CountryName : Explicit
	{
		// допустимые типы объекта
		public static bool IsValidTag(Tag tag) { return tag == Tag.Application(1); }

		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<NumericString  >().Factory(3, 3), Cast.N), 
			new ObjectInfo(new ObjectCreator<PrintableString>().Factory(2, 2), Cast.N), 
		}; 
		// конструктор при сериализации
        protected CountryName(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public CountryName(IEncodable encodable) : base(new Choice(info), encodable) {} 

		// конструктор при закодировании
		public CountryName(OctetString value) : base(new Choice(info), Tag.Application(1), value) {}  
	}
}

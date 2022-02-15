using System;

//	PhysicalDeliveryCountryName ::= CHOICE {
//		x121-dcc-code			NumericString	(SIZE (ub-country-name-numeric-length)),
//		iso-3166-alpha2-code	PrintableString	(SIZE (ub-country-name-alpha-length)) 
//	}
// ub-country-name-numeric-length	INTEGER ::= 3
// ub-country-name-alpha-length		INTEGER ::= 2

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	public class PhysicalDeliveryCountryName : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<NumericString  >().Factory(3, 3), Cast.N), 
			new ObjectInfo(new ObjectCreator<PrintableString>().Factory(2, 2), Cast.N), 
		}; 
		// конструктор
		public PhysicalDeliveryCountryName() : base(info) {} 
	}
}

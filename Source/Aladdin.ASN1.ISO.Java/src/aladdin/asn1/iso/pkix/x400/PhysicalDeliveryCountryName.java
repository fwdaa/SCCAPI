package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 

//	PhysicalDeliveryCountryName ::= CHOICE {
//		x121-dcc-code			NumericString	(SIZE (ub-country-name-numeric-length)),
//		iso-3166-alpha2-code	PrintableString	(SIZE (ub-country-name-alpha-length)) 
//	}
// ub-country-name-numeric-length	INTEGER ::= 3
// ub-country-name-alpha-length		INTEGER ::= 2

public final class PhysicalDeliveryCountryName extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(NumericString  .class).factory(3, 3), Cast.N), 
		new ObjectInfo(new ObjectCreator(PrintableString.class).factory(2, 2), Cast.N), 
	}; 
	// конструктор
	public PhysicalDeliveryCountryName() { super(info); } 
}

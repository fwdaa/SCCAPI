package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 

//	PrivateDomainName ::= CHOICE {
//		numeric   NumericString   (SIZE (1..ub-domain-name-length)),
//		printable PrintableString (SIZE (1..ub-domain-name-length)) 
//	}
//	ub-domain-name-length INTEGER ::= 16

public final class PrivateDomainName extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(NumericString  .class).factory(1, 16), Cast.N), 
		new ObjectInfo(new ObjectCreator(PrintableString.class).factory(1, 16), Cast.N), 
	}; 
	// конструктор
	public PrivateDomainName() { super(info); } 
}

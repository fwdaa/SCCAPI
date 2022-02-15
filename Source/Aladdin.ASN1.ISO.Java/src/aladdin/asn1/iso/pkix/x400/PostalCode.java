package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 

//	PostalCode ::= CHOICE {
//		numeric-code   NumericString   (SIZE (1..ub-postal-code-length)),
//		printable-code PrintableString (SIZE (1..ub-postal-code-length)) 
//	}
//	ub-postal-code-length INTEGER ::= 16

public final class PostalCode extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(NumericString  .class).factory(1, 16), Cast.N), 
		new ObjectInfo(new ObjectCreator(PrintableString.class).factory(1, 16), Cast.N), 
	}; 
	// конструктор
	public PostalCode() { super(info); } 
}


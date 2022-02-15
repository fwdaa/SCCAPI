package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 

//	DisplayText ::= CHOICE {
//		ia5String     IA5String      (SIZE (1..200)),
//		visibleString VisibleString  (SIZE (1..200)),
//		bmpString     BMPString      (SIZE (1..200)),
//		utf8String    UTF8String     (SIZE (1..200)) 
//	}

public final class DisplayText extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(IA5String      .class).factory(1, 200), Cast.N), 
		new ObjectInfo(new ObjectCreator(VisibleString  .class).factory(1, 200), Cast.N), 
		new ObjectInfo(new ObjectCreator(BMPString      .class).factory(1, 200), Cast.N), 
		new ObjectInfo(new ObjectCreator(UTF8String     .class).factory(1, 200), Cast.N), 
	}; 
	// конструктор
	public DisplayText() { super(info); } 
}

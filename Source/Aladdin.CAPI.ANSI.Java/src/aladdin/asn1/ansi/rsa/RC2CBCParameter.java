package aladdin.asn1.ansi.rsa;
import aladdin.asn1.*; 

///////////////////////////////////////////////////////////////////////////////
// RC2-CBCParameter ::= CHOICE {
//      iv OCTET STRING(8),
//      params SEQUENCE {
//          version INTEGER,
//          iv OCTET STRING(8)
//  }
// }
///////////////////////////////////////////////////////////////////////////////
public final class RC2CBCParameter extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString    .class).factory(8, 8), Cast.N), 
		new ObjectInfo(new ObjectCreator(RC2CBCParams   .class).factory(    ), Cast.N), 
	}; 
	// конструктор
	public RC2CBCParameter() { super(info); } 
}

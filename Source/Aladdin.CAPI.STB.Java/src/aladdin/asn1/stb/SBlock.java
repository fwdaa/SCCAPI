package aladdin.asn1.stb;
import aladdin.asn1.*; 

///////////////////////////////////////////////////////////////////////////////
// SBlockTable ::= OCTET STRING (SIZE(64))
// SBlock ::= CHOICE {
// 	table SBlockTable,
// 	oid OBJECT IDENTIFIER
// }
///////////////////////////////////////////////////////////////////////////////
public final class SBlock extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString     .class).factory(64, 64), Cast.N), 
		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(      ), Cast.N), 
	}; 
	// конструктор
	public SBlock() { super(info); } 
}

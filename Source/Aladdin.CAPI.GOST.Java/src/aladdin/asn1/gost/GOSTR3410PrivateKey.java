package aladdin.asn1.gost;
import aladdin.asn1.*; 

///////////////////////////////////////////////////////////////////////////////
//	GostR3410-2001-PrivateKey ::= CHOICE {
//		GostR3410-2001-KeyValueMask,
//		GostR3410-2001-KeyValueInfo 
// }
///////////////////////////////////////////////////////////////////////////////
public final class GOSTR3410PrivateKey extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString                 .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(GOSTR3410PrivateKeyValueInfo.class).factory(), Cast.N), 
	}; 
	// конструктор
	public GOSTR3410PrivateKey() { super(info); } 
}

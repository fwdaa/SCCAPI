package aladdin.asn1.iso.pkcs;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.*; 

//	String ::= CHOICE {
//		ia5String		IA5String		(SIZE(1..pkcs-9-ub-pkcs9String)),
//		directoryString DirectoryString (SIZE(0..pkcs-9-ub-pkcs9String))
//	}
//	pkcs-9-ub-pkcs9String INTEGER ::= 255

public final class PkcsString extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(IA5String      .class).factory(1, 255), Cast.N), 
		new ObjectInfo(new ChoiceCreator(DirectoryString.class).factory(0, 255), Cast.N), 
	}; 
	// конструктор
	public PkcsString() { super(info); } 
}

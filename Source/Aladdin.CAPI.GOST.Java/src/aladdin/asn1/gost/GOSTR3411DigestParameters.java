package aladdin.asn1.gost;
import aladdin.asn1.*; 

// DigestParameters ::= CHOCE { null NULL, oid OBJECT IDENTIFIER }; 

public final class GOSTR3411DigestParameters extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Null				.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(ObjectIdentifier	.class).factory(), Cast.N), 
	}; 
	// конструктор
	public GOSTR3411DigestParameters() { super(info); } 
}


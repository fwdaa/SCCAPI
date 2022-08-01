package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;
import aladdin.asn1.iso.pkix.*;

// 	ResponderID ::= CHOICE {
// 		byName   [1] EXPLICIT Name,
// 		byKey    [2] EXPLICIT OCTET STRING
// 	}

public final class ResponderID extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ChoiceCreator(Name       .class).factory(), Cast.E, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.E, Tag.context(1)), 
	}; 
	// конструктор
	public ResponderID() { super(info); } 
}

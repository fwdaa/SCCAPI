package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 

// Name ::= CHOICE { rdnSequence RelativeDistinguishedNames }

public final class Name extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(RelativeDistinguishedNames.class).factory(), Cast.N), 
	}; 
	// конструктор
	public Name() { super(info); } 
}

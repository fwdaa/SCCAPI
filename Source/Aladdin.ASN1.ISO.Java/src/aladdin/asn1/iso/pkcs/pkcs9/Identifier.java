package aladdin.asn1.iso.pkcs.pkcs9;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.*; 

//	Identifier ::= CHOICE {
//		string             UTF8String,
//		generalName        GeneralName
//	}

public class Identifier extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(UTF8String .class).factory(), Cast.N), 
		new ObjectInfo(new ChoiceCreator(GeneralName.class).factory(), Cast.N), 
	}; 
	// конструктор
	public Identifier() { super(info); } 
}

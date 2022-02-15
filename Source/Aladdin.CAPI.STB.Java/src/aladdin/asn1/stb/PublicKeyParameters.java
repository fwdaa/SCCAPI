package aladdin.asn1.stb;
import aladdin.asn1.*; 

///////////////////////////////////////////////////////////////////////////////
// PublicKeyParameters ::= CHOICE {
// 		bdsParams    [0] EXPLICIT BDSParams,
// 		bdhParams    [1] EXPLICIT BDHParams,
// 		bdsbdhParams [2] EXPLICIT BDSBDHParams
// 	}
///////////////////////////////////////////////////////////////////////////////
public final class PublicKeyParameters extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ChoiceCreator(BDSParams   .class).factory(), Cast.E, Tag.context(0)), 
		new ObjectInfo(new ChoiceCreator(BDHParams   .class).factory(), Cast.E, Tag.context(1)), 
		new ObjectInfo(new ChoiceCreator(BDSBDHParams.class).factory(), Cast.E, Tag.context(2)), 
	}; 
	// конструктор
	public PublicKeyParameters() { super(info); } 
}

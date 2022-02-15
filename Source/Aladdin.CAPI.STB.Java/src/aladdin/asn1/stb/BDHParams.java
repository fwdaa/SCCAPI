package aladdin.asn1.stb;
import aladdin.asn1.*; 

///////////////////////////////////////////////////////////////////////////////
// BDHParams ::= CHOICE {
// 		bdhParamsReference OBJECT IDENTIFIER,
// 		bdhParamsList BDHParamsList
// 	}
///////////////////////////////////////////////////////////////////////////////
public final class BDHParams extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(BDSParamsList	 .class).factory(), Cast.N), 
	}; 
	// конструктор
	public BDHParams() { super(info); } 
}

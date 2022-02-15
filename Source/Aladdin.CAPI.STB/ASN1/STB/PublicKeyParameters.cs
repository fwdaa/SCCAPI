namespace Aladdin.ASN1.STB
{
    ///////////////////////////////////////////////////////////////////////////////
    // PublicKeyParameters ::= CHOICE {
    // 		bdsParams    [0] EXPLICIT BDSParams,
    // 		bdhParams    [1] EXPLICIT BDHParams,
    // 		bdsbdhParams [2] EXPLICIT BDSBDHParams
    // 	}
    ///////////////////////////////////////////////////////////////////////////////
    public class PublicKeyParameters : Choice
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ChoiceCreator<BDSParams   >().Factory(), Cast.E, Tag.Context(0)), 
		    new ObjectInfo(new ChoiceCreator<BDHParams   >().Factory(), Cast.E, Tag.Context(1)), 
		    new ObjectInfo(new ChoiceCreator<BDSBDHParams>().Factory(), Cast.E, Tag.Context(2)), 
	    }; 
	    // конструктор
	    public PublicKeyParameters() : base(info) {} 
    }
}

namespace Aladdin.ASN1.STB
{
    ///////////////////////////////////////////////////////////////////////////////
    // BDSParams ::= CHOICE {
    // 		bdsParamsReference OBJECT IDENTIFIER,
    // 		bdsParamsList BDSParamsList
    // 	}
    ///////////////////////////////////////////////////////////////////////////////
    public class BDSParams : Choice
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<BDSParamsList	 >().Factory(), Cast.N), 
	    }; 
	    // конструктор
	    public BDSParams() : base(info) {} 
    }
}

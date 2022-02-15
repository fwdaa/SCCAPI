namespace Aladdin.ASN1.STB
{
    ////////////////////////////////////////////////////////////////////////////////
    // DomainParameters ::= CHOICE {
    //      specified ECParameters,
    //      named OBJECT IDENTIFIER,
    //      implicit NULL
    // }
    ////////////////////////////////////////////////////////////////////////////////
    public class DomainParameters : Choice
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<ECParameters    >().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<Null            >().Factory(), Cast.N), 
	    }; 
	    // конструктор
	    public DomainParameters() : base(info) {} 
    }
}

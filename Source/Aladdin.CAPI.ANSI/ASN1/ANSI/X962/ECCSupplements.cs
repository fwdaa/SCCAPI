namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // ECCSupplements ::= CHOICE {
    //      namedMultiples      [0] EXPLICIT NamedMultiples,
    //      specifiedMultiples  [1] EXPLICIT SpecifiedMultiples
    // }
    ////////////////////////////////////////////////////////////////////////////////
    public class ECCSupplements : Choice
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<NamedMultiples    >().Factory(), Cast.E, Tag.Context(0)), 
		    new ObjectInfo(new ObjectCreator<SpecifiedMultiples>().Factory(), Cast.E, Tag.Context(1)) 
	    }; 
	    // конструктор
	    public ECCSupplements() : base(info) {} 
    }
}

namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // ECDSA-Signature ::= CHOICE {
    //      two-ints-plus ECDSA-Sig-Value,
    //      point-int [0] EXPLICIT ECDSA-Full-R,
    // }
    ////////////////////////////////////////////////////////////////////////////////
    public class ECDSASignature : Choice
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<ECDSASigValue>().Factory(), Cast.N, Tag.Any       ), 
		    new ObjectInfo(new ObjectCreator<ECDSAFullR   >().Factory(), Cast.E, Tag.Context(0)) 
	    }; 
	    // конструктор
	    public ECDSASignature() : base(info) {} 
    }
}

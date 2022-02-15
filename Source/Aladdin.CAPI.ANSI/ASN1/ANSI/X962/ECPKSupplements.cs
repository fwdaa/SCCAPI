namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // ECPKSupplements ::= SEQUENCE {
    //      ecDomain ECDomainParameters {{ SECGCurveNames }},
    //      eccAlgorithms ECCAlgorithms,
    //      eccSupplements ECCSupplements
    // }
    ////////////////////////////////////////////////////////////////////////////////
    public class ECPKSupplements : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ChoiceCreator<ECDomainParameters>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<ECCAlgorithms     >().Factory(), Cast.N), 
		    new ObjectInfo(new ChoiceCreator<ECCSupplements    >().Factory(), Cast.N) 
	    }; 
	    // конструктор при раскодировании
	    public ECPKSupplements(IEncodable encodable) : base(encodable, info) {}

	    // конструктор при закодировании
	    public ECPKSupplements(IEncodable ecDomain, 
            ECCAlgorithms eccAlgorithms, IEncodable eccSupplements) 
                : base(info, ecDomain, eccAlgorithms, eccSupplements){}
 
	    public IEncodable     ECDomain        { get { return                this[0]; }}
	    public ECCAlgorithms  ECCAlgorithms   { get { return (ECCAlgorithms)this[1]; }}
	    public IEncodable     ECCSupplements  { get { return                this[2]; }}
    }
}

using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // ECPKRestrictions ::= SEQUENCE {
    //      ecDomain ECDomainParameters {{ SECGCurveNames }},
    //      eccAlgorithms ECCAlgorithms
    // }
    ////////////////////////////////////////////////////////////////////////////////
	[Serializable]
    public class ECPKRestrictions : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ChoiceCreator<ECDomainParameters>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<ECCAlgorithms     >().Factory(), Cast.N), 
	    }; 
		// конструктор при сериализации
        protected ECPKRestrictions(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public ECPKRestrictions(IEncodable encodable) : base(encodable, info) {}

	    // конструктор при закодировании
	    public ECPKRestrictions(IEncodable ecDomainParameters, ECCAlgorithms eccAlgorithms) 
            : base(info, ecDomainParameters, eccAlgorithms) {}
 
	    public IEncodable    ECDomainParameters { get { return                this[0]; }}
	    public ECCAlgorithms ECCAlgorithms      { get { return (ECCAlgorithms)this[1]; }}
    }
}

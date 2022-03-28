package aladdin.asn1.ansi.x962; 
import aladdin.asn1.*; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// ECPKRestrictions ::= SEQUENCE {
//      ecDomain ECDomainParameters {{ SECGCurveNames }},
//      eccAlgorithms ECCAlgorithms
// }
////////////////////////////////////////////////////////////////////////////////
public final class ECPKRestrictions extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -6699044103813447724L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ChoiceCreator(ECDomainParameters.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(ECCAlgorithms     .class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public ECPKRestrictions(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public ECPKRestrictions(IEncodable ecDomainParameters, ECCAlgorithms eccAlgorithms) 
    { 
        super(info, ecDomainParameters, eccAlgorithms); 
    }
	public final IEncodable    ecDomainParameters() { return                get(0); }
	public final ECCAlgorithms eccAlgorithms     () { return (ECCAlgorithms)get(1); }
}

package aladdin.asn1.ansi.x962;
import aladdin.asn1.*; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// ECPKSupplements ::= SEQUENCE {
//      ecDomain ECDomainParameters {{ SECGCurveNames }},
//      eccAlgorithms ECCAlgorithms,
//      eccSupplements ECCSupplements
// }
////////////////////////////////////////////////////////////////////////////////
public final class ECPKSupplements extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ChoiceCreator(ECDomainParameters .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(ECCAlgorithms      .class).factory(), Cast.N), 
		new ObjectInfo(new ChoiceCreator(ECCSupplements     .class).factory(), Cast.N) 
	}; 
	// конструктор при раскодировании
	public ECPKSupplements(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public ECPKSupplements(IEncodable ecDomain, 
        ECCAlgorithms eccAlgorithms, IEncodable eccSupplements) 
    { 
        super(info, ecDomain, eccAlgorithms, eccSupplements); 
    }
	public final IEncodable     ecDomain        () { return                get(0); }
	public final ECCAlgorithms  eccAlgorithms   () { return (ECCAlgorithms)get(1); }
	public final IEncodable     eccSupplements  () { return                get(2); }
}

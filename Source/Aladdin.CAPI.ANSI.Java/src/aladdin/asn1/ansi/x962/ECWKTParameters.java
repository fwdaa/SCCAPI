package aladdin.asn1.ansi.x962; 
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// ECWKTParameters ::= SEQUENCE {
//      kdf  [0] EXPLICIT KeyDerivationFunction OPTIONAL,
//      wrap [1] EXPLICIT KeyWrapFunction OPTIONAL
// }
////////////////////////////////////////////////////////////////////////////////
public final class ECWKTParameters extends Sequence<AlgorithmIdentifier>
{
    private static final long serialVersionUID = 8570973033010665712L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.EO, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.EO, Tag.context(1)) 
	}; 
	// конструктор при раскодировании
	public ECWKTParameters(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public ECWKTParameters(AlgorithmIdentifier kdf, AlgorithmIdentifier wrap) 
    { 
        super(info, kdf, wrap); 
    }
	public final AlgorithmIdentifier kdf () { return get(0); }
	public final AlgorithmIdentifier wrap() { return get(1); }
}

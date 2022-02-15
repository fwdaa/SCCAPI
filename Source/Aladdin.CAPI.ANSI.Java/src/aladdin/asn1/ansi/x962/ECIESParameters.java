package aladdin.asn1.ansi.x962; 
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// ECIESParameters ::= SEQUENCE {
//      kdf [0] EXPLICIT KeyDerivationFunction OPTIONAL,
//      sym [1] EXPLICIT SymmetricEncryption OPTIONAL,
//      mac [2] EXPLICIT MessageAuthenticationCode OPTIONAL
// }
////////////////////////////////////////////////////////////////////////////////
public final class ECIESParameters extends Sequence<AlgorithmIdentifier>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.EO, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.EO, Tag.context(1)), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.EO, Tag.context(2)), 
	}; 
	// конструктор при раскодировании
	public ECIESParameters(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public ECIESParameters(AlgorithmIdentifier kdf, 
        AlgorithmIdentifier sym, AlgorithmIdentifier mac) 
    { 
        super(info, kdf, sym, mac); 
    }
	public final AlgorithmIdentifier kdf() { return get(0); }
	public final AlgorithmIdentifier sym() { return get(1); }
	public final AlgorithmIdentifier mac() { return get(2); }
}

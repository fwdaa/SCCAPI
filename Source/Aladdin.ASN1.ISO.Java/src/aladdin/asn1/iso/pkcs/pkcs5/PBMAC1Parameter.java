package aladdin.asn1.iso.pkcs.pkcs5;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	PBMAC1Parameter ::= SEQUENCE {
//		keyDerivationFunc	AlgorithmIdentifier,
//		messageAuthScheme	AlgorithmIdentifier
//	}

public final class PBMAC1Parameter extends Sequence<AlgorithmIdentifier>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public PBMAC1Parameter(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public PBMAC1Parameter(AlgorithmIdentifier keyDerivationFunc, 
		AlgorithmIdentifier messageAuthScheme) 
	{
		super(info, keyDerivationFunc, messageAuthScheme); 
	}
	public final AlgorithmIdentifier	keyDerivationFunc() { return get(0); }
	public final AlgorithmIdentifier	messageAuthScheme() { return get(1); }
}

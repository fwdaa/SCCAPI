package aladdin.asn1.iso.pkcs.pkcs5;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	PBES2Parameter ::= SEQUENCE {
//		keyDerivationFunc	AlgorithmIdentifier,
//		encryptionScheme	AlgorithmIdentifier
//	}

public final class PBES2Parameter extends Sequence<AlgorithmIdentifier>
{
    private static final long serialVersionUID = -8253854200958284542L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public PBES2Parameter(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public PBES2Parameter(AlgorithmIdentifier keyDerivationFunc, 
		AlgorithmIdentifier encryptionScheme) 
	{
		super(info, keyDerivationFunc, encryptionScheme); 
	}
	public final AlgorithmIdentifier	keyDerivationFunc() { return get(0); }
	public final AlgorithmIdentifier	encryptionScheme () { return get(1); }
}


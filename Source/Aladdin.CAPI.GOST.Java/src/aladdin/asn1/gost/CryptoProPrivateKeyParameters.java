package aladdin.asn1.gost;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	GOSTRPrivateKeyParameters ::= SEQUENCE {
//		attributes			GostPrivateKeyAttributes,
//		privateKeyAlgorithm	[0] IMPLICIT AlgorithmIdentifier
//	}
//  GostPrivateKeyAttributes ::= BIT STRING {
//      pkaExportable(0), pkaUserProtect(1), pkaExchange(2), pkaEphemeral(3), pkaNonCachable(4)
//  }

public final class CryptoProPrivateKeyParameters extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

        new ObjectInfo(new ObjectCreator(BitString          .class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.N,	Tag.context(0)	), 
	}; 
	// конструктор при раскодировании
	public CryptoProPrivateKeyParameters(IEncodable encodable) throws IOException { super(encodable, info); }

    // конструктор при закодировании
	public CryptoProPrivateKeyParameters(BitString attributes, AlgorithmIdentifier privateKeyAlgorithm)
    {
        super(info, attributes, privateKeyAlgorithm); 
    }
	public final BitString              attributes		   () { return (BitString           )get(0); } 
	public final AlgorithmIdentifier    privateKeyAlgorithm() { return (AlgorithmIdentifier )get(1); }
}


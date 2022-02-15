package aladdin.asn1.iso.pkcs.pkcs1;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	RSASSA-PSS-params ::= SEQUENCE {
//		hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
//		maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
//		saltLength         [2] INTEGER            DEFAULT 20,
//		trailerField       [3] TrailerField       DEFAULT trailerFieldBC
//	}
//  TrailerField ::= INTEGER { trailerFieldBC(1) }

public final class RSASSAPSSParams extends Sequence<IEncodable>
{
	// значение по умолчанию
	private static final AlgorithmIdentifier sha1 = 
		new AlgorithmIdentifier(new ObjectIdentifier("1.3.14.3.2.26"), Null.INSTANCE);

	// значение по умолчанию
	private static final AlgorithmIdentifier mgf1_sha1 = 
		new AlgorithmIdentifier(new ObjectIdentifier(OID.RSA_MGF1), sha1); 

	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.EO, Tag.context(0), sha1				), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.EO, Tag.context(1), mgf1_sha1			), 
		new ObjectInfo(new ObjectCreator(Integer            .class).factory(), Cast.EO, Tag.context(2), new Integer(20)	), 
		new ObjectInfo(new ObjectCreator(Integer            .class).factory(), Cast.EO, Tag.context(3), new Integer( 1)	), 
	}; 
	// конструктор при раскодировании
	public RSASSAPSSParams(IEncodable encodable) throws IOException { super(encodable, info); 
	
		// проверить значение поля
		if (trailerField().value().intValue() > 0xFF) throw new IOException(); 
	}
	// конструктор при закодировании
	public RSASSAPSSParams(AlgorithmIdentifier hashAlgorithm, AlgorithmIdentifier maskGenAlgorithm, 
		Integer saltLength, Integer trailerField) 
	{
		super(info, hashAlgorithm, maskGenAlgorithm, saltLength, trailerField); 
				
		// проверить значение поля
		if (trailerField.value().intValue() > 0xFF) throw new IllegalArgumentException(); 
	}
	public final AlgorithmIdentifier	hashAlgorithm	() { return (AlgorithmIdentifier)get(0); } 
	public final AlgorithmIdentifier    maskGenAlgorithm() { return (AlgorithmIdentifier)get(1); }
	public final Integer                saltLength		() { return (Integer            )get(2); }
	public final Integer                trailerField	() { return (Integer            )get(3); }
}


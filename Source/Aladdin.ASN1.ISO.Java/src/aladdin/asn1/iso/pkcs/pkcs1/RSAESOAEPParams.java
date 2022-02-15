package aladdin.asn1.iso.pkcs.pkcs1;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	RSAES-OAEP-params ::= SEQUENCE {
//		hashAlgorithm      [0] EXPLICIT AlgorithmIdentifier DEFAULT sha1,
//		maskGenAlgorithm   [1] EXPLICIT AlgorithmIdentifier DEFAULT mgf1SHA1,
//		pSourceAlgorithm   [2] EXPLICIT AlgorithmIdentifier DEFAULT pSpecifiedEmpty
//	}

public final class RSAESOAEPParams extends Sequence<AlgorithmIdentifier>
{
	// значение по умолчанию
	private static final OctetString empty = new OctetString(new byte[0]); 
	
	// значение по умолчанию
	private static final AlgorithmIdentifier pSpecifiedEmpty = 
		new AlgorithmIdentifier(new ObjectIdentifier(OID.RSA_SPECIFIED), empty); 
		
	// значение по умолчанию
	private static final AlgorithmIdentifier sha1 = 
		new AlgorithmIdentifier(new ObjectIdentifier("1.3.14.3.2.26"), Null.INSTANCE);

	// значение по умолчанию
	private static final AlgorithmIdentifier mgf1_sha1 = 
		new AlgorithmIdentifier(new ObjectIdentifier(OID.RSA_MGF1), sha1); 

	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.EO, Tag.context(0), sha1			), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.EO, Tag.context(1), mgf1_sha1		), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(), Cast.EO, Tag.context(2), pSpecifiedEmpty), 
	}; 
	// конструктор при раскодировании
	public RSAESOAEPParams(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public RSAESOAEPParams(AlgorithmIdentifier hashAlgorithm, 
		AlgorithmIdentifier maskGenAlgorithm, AlgorithmIdentifier pSourceAlgorithm) 
	{
		super(info, hashAlgorithm, maskGenAlgorithm, pSourceAlgorithm); 
	}
	public final AlgorithmIdentifier	hashAlgorithm	() { return get(0); } 
	public final AlgorithmIdentifier	maskGenAlgorithm() { return get(1); }
	public final AlgorithmIdentifier	pSourceAlgorithm() { return get(2); }
	public final OctetString            label			() 
	{
		// проверить тип метки
		if (!pSourceAlgorithm().algorithm().value().equals(OID.RSA_SPECIFIED)) return empty;
		try { 	
			// получить значение метки
			return new OctetString(pSourceAlgorithm().parameters()); 
		}
		// обработать возможное исключение
		catch (Exception e) { throw new RuntimeException(e); }
	}
}

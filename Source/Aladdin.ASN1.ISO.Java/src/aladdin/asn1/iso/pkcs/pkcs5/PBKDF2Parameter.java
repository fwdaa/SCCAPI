package aladdin.asn1.iso.pkcs.pkcs5;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*; 

//	PBKDF2Parameter ::= SEQUENCE {
//		salt			PBSalt,
//		iterationCount	INTEGER (1..MAX),
//		keyLength		INTEGER (1..MAX)	OPTIONAL,
//		prf				AlgorithmIdentifier DEFAULT hmac_sha1
//	}

public final class PBKDF2Parameter extends Sequence<IEncodable>
{
	// значение псевдослучайной функции по умолчанию
	private static final AlgorithmIdentifier prf = new AlgorithmIdentifier(
        new ObjectIdentifier("1.2.840.113549.2.7"), Null.INSTANCE
    );  
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 
        new ObjectInfo(new ChoiceCreator(PBSalt				.class).factory( ), Cast.N,	Tag.ANY		), 
		new ObjectInfo(new ObjectCreator(Integer            .class).factory(1), Cast.N,	Tag.ANY		), 
		new ObjectInfo(new ObjectCreator(Integer            .class).factory(1), Cast.O,	Tag.ANY		), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory( ), Cast.O,	Tag.ANY, prf), 
	}; 
	// конструктор при раскодировании
	public PBKDF2Parameter(IEncodable encodable) throws IOException { super(encodable, info); } 
	
	// конструктор при закодировании
	public PBKDF2Parameter(IEncodable salt,  Integer iterationCount, 
		 Integer keyLength, AlgorithmIdentifier prf) 
	{
		super(info, salt, iterationCount, keyLength, prf); 
	}
	public final IEncodable             salt			() { return						 get(0); }
	public final Integer                iterationCount	() { return (Integer            )get(1); }
	public final Integer                keyLength		() { return (Integer            )get(2); }
	public final AlgorithmIdentifier	prf				() { return (AlgorithmIdentifier)get(3); }
}

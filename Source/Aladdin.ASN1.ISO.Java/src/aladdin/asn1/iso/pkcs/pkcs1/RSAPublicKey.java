package aladdin.asn1.iso.pkcs.pkcs1;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

//	RSAPublicKey ::= SEQUENCE {
//		modulus			INTEGER,
//		publicExponent	INTEGER
//	}

public final class RSAPublicKey extends Sequence<Integer>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public RSAPublicKey(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public RSAPublicKey(Integer modulus, Integer publicExponent) 
	{
		super(info, modulus, publicExponent); 
	}
	public final Integer modulus		() { return get(0); } 
	public final Integer publicExponent	() { return get(1); }
}

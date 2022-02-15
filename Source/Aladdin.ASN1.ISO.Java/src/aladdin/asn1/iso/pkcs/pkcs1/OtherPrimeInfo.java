package aladdin.asn1.iso.pkcs.pkcs1;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

//	OtherPrimeInfo ::= SEQUENCE {
//		prime		INTEGER, 
//		exponent	INTEGER, 
//		coefficient INTEGER 
//}
public final class OtherPrimeInfo extends Sequence<Integer>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public OtherPrimeInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public OtherPrimeInfo(Integer prime, Integer exponent, 
		Integer coefficient) 
	{
		super(info, prime, exponent, coefficient); 
	}
	public final Integer prime          () { return get(0); } 
	public final Integer exponent       () { return get(1); }
	public final Integer coefficient	() { return get(2); }
}

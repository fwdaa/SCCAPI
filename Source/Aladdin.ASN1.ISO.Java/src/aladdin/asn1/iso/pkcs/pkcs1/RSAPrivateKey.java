package aladdin.asn1.iso.pkcs.pkcs1;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

//	RSAPrivateKey ::= SEQUENCE {
//		version			INTEGER,
//		modulus			INTEGER, 
//		publicExponent	INTEGER, 
//		privateExponent INTEGER, 
//		prime1			INTEGER, 
//		prime2			INTEGER, 
//		exponent1		INTEGER, 
//		exponent2		INTEGER, 
//		coefficient		INTEGER,
//		otherPrimeInfos OtherPrimeInfos OPTIONAL
//}

public final class RSAPrivateKey extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -6546266204791370795L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer        .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer        .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer        .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer        .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer        .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer        .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer        .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer        .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer        .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OtherPrimeInfos.class).factory(), Cast.O), 
	}; 
	// конструктор при раскодировании
	public RSAPrivateKey(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public RSAPrivateKey(Integer version, Integer modulus, Integer publicExponent, 
		Integer privateExponent, Integer prime1, Integer prime2, Integer exponent1, 
		Integer exponent2, Integer coefficient, OtherPrimeInfos otherPrimeInfos) 
	{
		super(info, version, modulus, publicExponent, privateExponent, 
			prime1, prime2, exponent1, exponent2, coefficient, otherPrimeInfos); 
	}
	public final Integer            version			() { return (Integer        )get(0); } 
	public final Integer            modulus			() { return (Integer        )get(1); } 
	public final Integer            publicExponent	() { return (Integer        )get(2); }
	public final Integer            privateExponent	() { return (Integer        )get(3); } 
	public final Integer            prime1			() { return (Integer        )get(4); }
	public final Integer            prime2			() { return (Integer        )get(5); } 
	public final Integer            exponent1		() { return (Integer        )get(6); }
	public final Integer            exponent2		() { return (Integer        )get(7); } 
	public final Integer            coefficient		() { return (Integer        )get(8); }
	public final OtherPrimeInfos    otherPrimeInfos	() { return (OtherPrimeInfos)get(9); }
}

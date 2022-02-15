package aladdin.asn1.iso.pkcs.pkcs3;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*;

//	DHParameter ::= SEQUENCE {
//		prime				INTEGER, 
//		base				INTEGER, 
//		privateValueLength	INTEGER OPTIONAL
//	}

public final class DHParameter extends Sequence<Integer>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.O), 
	}; 
	// конструктор при раскодировании
	public DHParameter(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public DHParameter(Integer prime, Integer base, Integer privateValueLength) 
	{
		super(info, prime, base, privateValueLength); 
	}
	public final Integer prime				() { return get(0); } 
	public final Integer base               () { return get(1); }
	public final Integer privateValueLength	() { return get(2); }
}

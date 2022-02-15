package aladdin.asn1.gost;
import aladdin.asn1.*; 
import java.io.*; 

//	GOST28147Parameters ::= SEQUENCE {
//		iv                   OCTET STRING (SIZE (8)),
//		encryptionParamSet   OBJECT IDENTIFIER
//	}

public final class GOST28147CipherParameters extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString		.class).factory(8, 8), Cast.N), 
		new ObjectInfo(new ObjectCreator(ObjectIdentifier	.class).factory(    ), Cast.N), 
	}; 
	// конструктор при раскодировании
	public GOST28147CipherParameters(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public GOST28147CipherParameters(OctetString iv, ObjectIdentifier paramSet)
	{
		// проверить ограничение
		super(info, iv, paramSet); 
	}  
	public final OctetString		iv		()	{ return (OctetString	  )get(0); } 
	public final ObjectIdentifier	paramSet()	{ return (ObjectIdentifier)get(1); }
}

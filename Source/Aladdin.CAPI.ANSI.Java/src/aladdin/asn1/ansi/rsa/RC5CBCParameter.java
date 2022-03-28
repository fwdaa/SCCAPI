package aladdin.asn1.ansi.rsa; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

// RC5-CBC-Parameters ::= SEQUENCE {
//		version		INTEGER	{v1-0(16)} (v1-0),
//		rounds		INTEGER	(0..127),
//		blockSize	INTEGER	(64 | 128),
//		iv			OCTET STRING OPTIONAL
//	}

public final class RC5CBCParameter extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -5259285225252509063L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer    .class).factory(       ), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer	.class).factory( 0, 127), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer	.class).factory(64, 128), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(       ), Cast.O), 
	}; 
	// конструктор при раскодировании
	public RC5CBCParameter(IEncodable encodable) throws IOException
	{
        super(encodable, info); 
        
		// проверить ограничение
		if (blockSize().value().intValue() != 64 && blockSize().value().intValue() != 128) 
		{
			// при ошибке выбросить исключение
			throw new IOException(); 
		}
	}
	// конструктор при закодировании
	public RC5CBCParameter(Integer version, Integer rounds, 
        Integer blockSize, OctetString iv) 
	{
        super(info, version, rounds, blockSize, iv); 
        
		// проверить ограничение
		if (blockSize().value().intValue() != 64 && blockSize().value().intValue() != 128) 
		{
			// при ошибке выбросить исключение
			throw new IllegalArgumentException(); 
		}
    }
	public final Integer		version  ()	{ return (Integer       )get(0); }
	public final Integer		rounds	 ()	{ return (Integer       )get(1); }
	public final Integer		blockSize()	{ return (Integer       )get(2); }
	public final OctetString	iv		 ()	{ return (OctetString   )get(3); }
}


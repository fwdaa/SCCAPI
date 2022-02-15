package aladdin.asn1.ansi.rsa; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

//	RC2CBCParameter ::= SEQUENCE {
//		parameterVersion	INTEGER(1, 1024), 
//		iv					OCTET STRING (SIZE(8))
//	}

public final class RC2CBCParams extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

        new ObjectInfo(new ObjectCreator(Integer    .class).factory(1, 1024), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(8,    8), Cast.N), 
	}; 
	// конструктор при раскодировании
	public RC2CBCParams(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public RC2CBCParams(Integer parameterVersion, OctetString iv)
	{
		// вызвать базовую функцию
		super(info, parameterVersion, iv); 
	}
    public final Integer		parameterVersion()	{ return (Integer       )get(0); }
	public final OctetString	iv				()	{ return (OctetString   )get(1); }
}

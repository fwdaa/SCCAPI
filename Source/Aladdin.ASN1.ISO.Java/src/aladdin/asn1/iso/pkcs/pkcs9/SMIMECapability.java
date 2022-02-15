package aladdin.asn1.iso.pkcs.pkcs9;
import aladdin.asn1.*; 
import java.io.*; 

//	SMIMECapability  ::=  SEQUENCE  {
//		algorithm  OBJECT IDENTIFIER,
//		parameters ANY DEFINED BY algorithm
//	}

public final class SMIMECapability extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(    ImplicitCreator						.factory  , Cast.N), 
	}; 
	// конструктор при раскодировании
	public SMIMECapability(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public SMIMECapability(ObjectIdentifier algorithm, IEncodable parameters) 
	{
		super(info, algorithm, parameters); 
	}
	public final ObjectIdentifier	algorithm	() { return (ObjectIdentifier)get(0); } 
	public final IEncodable         parameters	() { return                   get(1); }
}

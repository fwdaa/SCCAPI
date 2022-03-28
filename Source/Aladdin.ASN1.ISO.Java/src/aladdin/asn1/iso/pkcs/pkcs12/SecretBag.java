package aladdin.asn1.iso.pkcs.pkcs12;
import aladdin.asn1.*; 
import java.io.*; 

//	SecretBag ::= SEQUENCE {
//		secretTypeId				 OBJECT IDENTIFIER,
//		secretValue		[0] EXPLICIT ANY DEFINED BY secretTypeId
//	}

public final class SecretBag extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 599396725636019607L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N,	Tag.ANY			), 
		new ObjectInfo(    ImplicitCreator				        .factory  , Cast.E,	Tag.context(0)	), 
	}; 
	// конструктор при раскодировании
	public SecretBag(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public SecretBag(ObjectIdentifier secretTypeId, IEncodable secretValue) 
	{
		super(info, secretTypeId, secretValue); 
	}
	public final ObjectIdentifier secretTypeId  () { return (ObjectIdentifier)get(0); } 
	public final IEncodable		  secretValue	() { return                   get(1); }
}

package aladdin.asn1.iso.pkcs.pkcs9;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*;
import java.io.*;

//	EncKeyWithID ::= SEQUENCE {
//		privateKey      PrivateKeyInfo,
//		identifier		Identifier OPTIONAL
//	}

public final class EncKeyWithID extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 6209488170470458607L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(PrivateKeyInfo	.class).factory(), Cast.N), 
		new ObjectInfo(new ChoiceCreator(Identifier		.class).factory(), Cast.O), 
	}; 
	// конструктор при раскодировании
	public EncKeyWithID(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public EncKeyWithID(PrivateKeyInfo privateKey, IEncodable identifier) 
	{
		super(info, privateKey, identifier); 
	}
	public final PrivateKeyInfo	privateKey()	{ return (PrivateKeyInfo)get(0); } 
	public final IEncodable     identifier()	{ return				 get(1); }
}

package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import java.io.*; 

//	OtherRecipientInfo ::= SEQUENCE {
//		oriType		OBJECT IDENTIFIER,
//		oriValue	ANY DEFINED BY oriType 
//	}

public final class OtherRecipientInfo extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 2144762522291049859L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(    ImplicitCreator					    .factory  , Cast.N), 
	}; 
	// конструктор при раскодировании
	public OtherRecipientInfo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public OtherRecipientInfo(ObjectIdentifier oriType, IEncodable oriValue) 
	{
		super(info, oriType, oriValue); 
	}
	public final ObjectIdentifier	oriType	() { return (ObjectIdentifier)get(0); } 
	public final IEncodable         oriValue() { return                   get(1); }
}

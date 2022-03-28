package aladdin.asn1.iso.pkcs.pkcs7;
import aladdin.asn1.*; 
import java.io.*; 

//	OtherKeyAttribute ::= SEQUENCE {
//		keyAttrId	OBJECT IDENTIFIER,
//		keyAttr		ANY DEFINED BY keyAttrId OPTIONAL 
//	}

public final class OtherKeyAttribute extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 266929408628208859L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(    ImplicitCreator						.factory  , Cast.O), 
	}; 
	// конструктор при раскодировании
	public OtherKeyAttribute(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public OtherKeyAttribute(ObjectIdentifier keyAttrId, IEncodable keyAttr) 
	{
		super(info, keyAttrId, keyAttr); 
	}
	public final ObjectIdentifier	keyAttrId() { return (ObjectIdentifier)get(0); } 
	public final IEncodable         keyAttr	 () { return                   get(1); }
}

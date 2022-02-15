package aladdin.asn1.gost;
import aladdin.asn1.*; 
import java.io.*; 

//	GOST28147KeyWrapParameters ::= SEQUENCE {
//		encryptionParamSet OBJECT IDENTIFIER,
//		ukm                OCTET STRING (SIZE (8..16)) OPTIONAL
//	}

public final class KeyWrapParameters extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier   .class).factory(     ), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString		.class).factory(8, 16), Cast.O), 
	}; 
	// конструктор при раскодировании
	public KeyWrapParameters(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public KeyWrapParameters(ObjectIdentifier encryptionParamSet, OctetString ukm)
	{
        super(info, encryptionParamSet, ukm); 
    }  
	public final ObjectIdentifier	paramSet() { return (ObjectIdentifier   )get(0); }
	public final OctetString		ukm		() { return (OctetString        )get(1); } 
}

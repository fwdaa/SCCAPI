package aladdin.asn1.stb;
import aladdin.asn1.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
//	BDHParamsInitData ::= SEQUENCE {
//		bdhPrmsInitZSequence OCTET STRING,
//		bdhPrmsInitLSequence OCTET STRING
//	}
///////////////////////////////////////////////////////////////////////////////
public final class BDHParamsInitData extends Sequence<IEncodable> 
{
    private static final long serialVersionUID = -7459724779205587812L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 
        
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public BDHParamsInitData(IEncodable encodable) throws IOException { super(encodable, info); }  
    
	// конструктор при закодировании
	public BDHParamsInitData(OctetString bdhPrmsInitZSequence, 
        OctetString bdhPrmsInitLSequence)
	{
		super(info, bdhPrmsInitZSequence, bdhPrmsInitLSequence); 
	}
	public final OctetString bdhPrmsInitZSequence() { return (OctetString)get(0); } 
	public final OctetString bdhPrmsInitLSequence() { return (OctetString)get(1); } 
}

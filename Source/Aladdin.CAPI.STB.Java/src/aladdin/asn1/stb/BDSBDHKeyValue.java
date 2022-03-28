package aladdin.asn1.stb;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// BDSKeyValue ::= INTEGER
// BDSBDHKeyValue ::= SEQUENCE {
// 		bdsKey INTEGER,
// 		bdhKey INTEGER
// 	}
///////////////////////////////////////////////////////////////////////////////
public final class BDSBDHKeyValue extends Sequence<Integer> 
{
    private static final long serialVersionUID = -717962434006509785L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 
        
		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N),
		new ObjectInfo(new ObjectCreator(Integer.class).factory(), Cast.N) 
	}; 
	// конструктор при раскодировании
	public BDSBDHKeyValue(IEncodable encodable) throws IOException { super(encodable, info); }  
    
	// конструктор при закодировании
	public BDSBDHKeyValue(Integer bdsKey, Integer bdhKey)
	{
		super(info, bdsKey, bdhKey); 
	}
	public final Integer bdsKey() { return get(0); } 
	public final Integer bdhKey() { return get(1); } 
}

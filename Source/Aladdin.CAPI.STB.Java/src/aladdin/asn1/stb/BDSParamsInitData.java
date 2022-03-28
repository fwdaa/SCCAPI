package aladdin.asn1.stb;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
//	BDSParamsInitData ::= SEQUENCE {
//		bdsPrmsInitZSequence OCTET STRING,
//		bdsPrmsInitDSequence OCTET STRING,
//		bdsPrmsInitRSequence OCTET STRING,
//		bdsPrmsInitDValue INTEGER
//	}
///////////////////////////////////////////////////////////////////////////////
public final class BDSParamsInitData extends Sequence<IEncodable> 
{
    private static final long serialVersionUID = -2569735020584670722L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 
        
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer    .class).factory(), Cast.N) 
	}; 
	// конструктор при раскодировании
	public BDSParamsInitData(IEncodable encodable) throws IOException { super(encodable, info); }  
    
	// конструктор при закодировании
	public BDSParamsInitData(OctetString bdsPrmsInitZSequence, 
        OctetString bdsPrmsInitDSequence, OctetString bdsPrmsInitRSequence, 
        Integer bdsPrmsInitDValue)
	{
		super(info, bdsPrmsInitZSequence, bdsPrmsInitDSequence,
            bdsPrmsInitRSequence, bdsPrmsInitDValue); 
	}
	public final OctetString bdsPrmsInitZSequence() { return (OctetString)get(0); } 
	public final OctetString bdsPrmsInitDSequence() { return (OctetString)get(1); } 
	public final OctetString bdsPrmsInitRSequence() { return (OctetString)get(2); } 
	public final Integer     bdsPrmsInitDValue   () { return (Integer	 )get(3); } 
}

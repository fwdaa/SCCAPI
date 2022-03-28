package aladdin.asn1.gost;
import aladdin.asn1.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Стандарт ГОСТ R34.10-2012
///////////////////////////////////////////////////////////////////////////////
//	GOSTR3410PublicKeyParameters ::= SEQUENCE {
//		publicKeyParamSet	OBJECT IDENTIFIER,
//		digestParamSet		OBJECT IDENTIFIER OPTIONAL
//	}

public final class GOSTR3410PublicKeyParameters2012 extends Sequence<ObjectIdentifier>
{
    private static final long serialVersionUID = -5802575844014916629L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.O) 
	}; 
	// конструктор при раскодировании
	public GOSTR3410PublicKeyParameters2012(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public GOSTR3410PublicKeyParameters2012(ObjectIdentifier publicKeyParamSet, 
		ObjectIdentifier digestParamSet)  
    {
        super(info, publicKeyParamSet, digestParamSet); 
    }
    public final ObjectIdentifier publicKeyParamSet () { return get(0); } 
	public final ObjectIdentifier digestParamSet	() { return get(1); }
}


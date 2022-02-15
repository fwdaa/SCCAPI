package aladdin.asn1.gost;
import aladdin.asn1.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Стандарт ГОСТ R34.10-1994,2001
///////////////////////////////////////////////////////////////////////////////
//	GOSTR3410PublicKeyParameters ::= SEQUENCE {
//		publicKeyParamSet	OBJECT IDENTIFIER,
//		digestParamSet		OBJECT IDENTIFIER,
//		encryptionParamSet	OBJECT IDENTIFIER	DEFAULT CryptoPro-A-ParamSet
//	}

public final class GOSTR3410PublicKeyParameters2001 extends Sequence<ObjectIdentifier>
{
	// значение идентификатора по умолчанию
	private static final ObjectIdentifier def = new ObjectIdentifier(OID.ENCRYPTS_A); 

	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N,	Tag.ANY		), 
		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N,	Tag.ANY		), 
		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.O,	Tag.ANY, def), 
	}; 
	// конструктор при раскодировании
	public GOSTR3410PublicKeyParameters2001(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public GOSTR3410PublicKeyParameters2001(ObjectIdentifier publicKeyParamSet, 
		ObjectIdentifier digestParamSet, ObjectIdentifier encryptionParamSet)  
    {
        super(info, publicKeyParamSet, digestParamSet, encryptionParamSet); 
    }
    public final ObjectIdentifier publicKeyParamSet () { return get(0); } 
	public final ObjectIdentifier digestParamSet	() { return get(1); }
	public final ObjectIdentifier encryptionParamSet() { return get(2); }
}


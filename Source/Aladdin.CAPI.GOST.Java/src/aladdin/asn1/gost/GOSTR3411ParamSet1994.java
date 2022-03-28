package aladdin.asn1.gost;
import aladdin.asn1.*; 
import java.io.*; 
import java.util.*; 

//	GOSTR3411ParamSet ::= SEQUENCE {
//		hUZ OCTET STRING (SIZE(64)),    
//		h0  OCTET STRING (SIZE(32))
//	}

public final class GOSTR3411ParamSet1994 extends Sequence<OctetString>
{
    private static final long serialVersionUID = 5276152301978876141L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

        new ObjectInfo(new ObjectCreator(OctetString.class).factory(64, 64), Cast.N), 
		new ObjectInfo(new ObjectCreator(OctetString.class).factory(32, 32), Cast.N), 
	}; 
	// конструктор при раскодировании
	public GOSTR3411ParamSet1994(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public GOSTR3411ParamSet1994(OctetString hUZ, OctetString h0)
	{
        super(info, hUZ, h0); 
	}  
	public final OctetString huz() { return get(0); } 
	public final OctetString h0	() { return get(1); }
    
	// стартовое значение
	private static final byte[] H0_TEST = new byte[] {
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
	}; 
	private static final byte[] H0_CRYPTOPRO = new byte[] {
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
	}; 
	// таблица именованных параметров
	private static final Map<String, GOSTR3411ParamSet1994> set = 
		new HashMap<String, GOSTR3411ParamSet1994>(); 
	static {
		set.put(OID.HASHES_TEST, new GOSTR3411ParamSet1994(
			GOST28147SBoxReference.parameters(OID.HASHES_TEST), 
            new OctetString(H0_TEST)
		)); 
		set.put(OID.HASHES_CRYPTOPRO, new GOSTR3411ParamSet1994(
			GOST28147SBoxReference.parameters(OID.HASHES_CRYPTOPRO), 
            new OctetString(H0_CRYPTOPRO)
		)); 
	}
	// получить именованные параметры
	public static GOSTR3411ParamSet1994 parameters(String oid) { return set.get(oid); } 
}

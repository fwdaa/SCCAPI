package aladdin.asn1.gost;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import java.io.*; 
import java.util.*; 

//	GOST28147ParamSet ::= SEQUENCE {
//		eUZ             OCTET STRING (SIZE(64)),
//		mode            Mode,
//		shiftBits       INTEGER { block(64) },
//		keyMeshing      AlgorithmIdentifier
//	}

public final class GOST28147ParamSet extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 5664468076131092762L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(OctetString		.class).factory(64, 64), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer			.class).factory(      ), Cast.N), 
		new ObjectInfo(new ObjectCreator(Integer			.class).factory(64, 64), Cast.N), 
		new ObjectInfo(new ObjectCreator(AlgorithmIdentifier.class).factory(      ), Cast.N), 
	}; 
	// конструктор при раскодировании
	public GOST28147ParamSet(IEncodable encodable) throws IOException { super(encodable, info); }
    
	// конструктор при закодировании
	public GOST28147ParamSet(OctetString eUZ, Integer mode, 
        Integer shiftBits, AlgorithmIdentifier keyMeshing)
	{
        super(info, eUZ, mode, shiftBits, keyMeshing); 
	}  
	public final OctetString            euz       () { return (OctetString          )get(0); } 
	public final Integer                mode	  () { return (Integer              )get(1); }
	public final Integer                shiftBits () { return (Integer              )get(2); }
	public final AlgorithmIdentifier	keyMeshing() { return (AlgorithmIdentifier	)get(3); }
    
	// таблица именованных параметров
	private static final Map<String, GOST28147ParamSet> set = 
		new HashMap<String, GOST28147ParamSet>(); 
    static {
		set.put(OID.ENCRYPTS_TEST, new GOST28147ParamSet(
			GOST28147SBoxReference.parameters(OID.ENCRYPTS_TEST), 
            new Integer(GOST28147CipherMode.CTR.value()), 
            new Integer(64), new AlgorithmIdentifier(
                new ObjectIdentifier(OID.KEY_MESHING_NONE), 
                Null.INSTANCE
        ))); 
		set.put(OID.ENCRYPTS_A, new GOST28147ParamSet(
			GOST28147SBoxReference.parameters(OID.ENCRYPTS_A), 
            new Integer(GOST28147CipherMode.CFB.value()), 
            new Integer(64), new AlgorithmIdentifier(
                new ObjectIdentifier(OID.KEY_MESHING_CRYPTOPRO), 
                Null.INSTANCE
        ))); 
		set.put(OID.ENCRYPTS_B, new GOST28147ParamSet(
			GOST28147SBoxReference.parameters(OID.ENCRYPTS_B), 
            new Integer(GOST28147CipherMode.CFB.value()), 
            new Integer(64), new AlgorithmIdentifier(
                new ObjectIdentifier(OID.KEY_MESHING_CRYPTOPRO), 
                Null.INSTANCE
        ))); 
		set.put(OID.ENCRYPTS_C, new GOST28147ParamSet(
			GOST28147SBoxReference.parameters(OID.ENCRYPTS_C), 
            new Integer(GOST28147CipherMode.CFB.value()), 
            new Integer(64), new AlgorithmIdentifier(
                new ObjectIdentifier(OID.KEY_MESHING_CRYPTOPRO), 
                Null.INSTANCE
        ))); 
		set.put(OID.ENCRYPTS_D, new GOST28147ParamSet(
			GOST28147SBoxReference.parameters(OID.ENCRYPTS_D), 
            new Integer(GOST28147CipherMode.CFB.value()), 
            new Integer(64), new AlgorithmIdentifier(
                new ObjectIdentifier(OID.KEY_MESHING_CRYPTOPRO), 
                Null.INSTANCE
        ))); 
		set.put(OID.ENCRYPTS_TC26_Z, new GOST28147ParamSet(
			GOST28147SBoxReference.parameters(OID.ENCRYPTS_TC26_Z), 
            new Integer(GOST28147CipherMode.CFB.value()), 
            new Integer(64), new AlgorithmIdentifier(
                new ObjectIdentifier(OID.KEY_MESHING_CRYPTOPRO), 
                Null.INSTANCE
        ))); 
	}
	// получить именованные параметры
	public static GOST28147ParamSet parameters(String oid) { return set.get(oid); } 
}

package aladdin.asn1.stb;
import aladdin.asn1.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////////
// BDSBDHParamsList ::= SEQUENCE {
// 		bdsParamsList BDSParamsList,
// 		bdhParamsList BDHParamsList
// 	}
///////////////////////////////////////////////////////////////////////////////
public final class BDSBDHParamsList extends Sequence<IEncodable>
{
    private static final long serialVersionUID = 1277757244004744677L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(BDSParamsList.class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(BDHParamsList.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public BDSBDHParamsList(IEncodable encodable) throws IOException { super(encodable, info); }

    // конструктор при закодировании
	public BDSBDHParamsList(BDSParamsList bdsParamsList, BDHParamsList bdhParamsList)
    {
        super(info, bdsParamsList, bdhParamsList); 
    }
	public final BDSParamsList	bdsParamsList() { return (BDSParamsList)get(0); } 
	public final BDHParamsList  bdhParamsList() { return (BDHParamsList)get(1); }
    
	///////////////////////////////////////////////////////////////////////////
	// Таблица именованных параметров
	///////////////////////////////////////////////////////////////////////////
	private static final Map<String, BDSBDHParamsList> set = 
        new HashMap<String, BDSBDHParamsList>(); 
	static {
		set.put(OID.STB11762_PARAMS3, new BDSBDHParamsList(
            BDSParamsList.parameters(OID.STB11762_PARAMS3_BDS), 
            BDHParamsList.parameters(OID.STB11762_PARAMS3_BDH) 
        )); 
		set.put(OID.STB11762_PARAMS6, new BDSBDHParamsList(
            BDSParamsList.parameters(OID.STB11762_PARAMS6_BDS), 
            BDHParamsList.parameters(OID.STB11762_PARAMS6_BDH) 
        )); 
		set.put(OID.STB11762_PARAMS10, new BDSBDHParamsList(
            BDSParamsList.parameters(OID.STB11762_PARAMS10_BDS), 
            BDHParamsList.parameters(OID.STB11762_PARAMS10_BDH) 
        )); 
	}
	// получить именованные параметры
	public static BDSBDHParamsList parameters(String oid) { return set.get(oid); } 
    
}

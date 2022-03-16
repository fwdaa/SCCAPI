using System; 
using System.Collections.Generic;
using System.Runtime.Serialization;

namespace Aladdin.ASN1.STB
{
    ///////////////////////////////////////////////////////////////////////////////
    // BDSBDHParamsList ::= SEQUENCE {
    // 		bdsParamsList BDSParamsList,
    // 		bdhParamsList BDHParamsList
    // 	}
    ///////////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class BDSBDHParamsList : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ObjectCreator<BDSParamsList>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<BDHParamsList>().Factory(), Cast.N), 
	    }; 
		// конструктор при сериализации
        protected BDSBDHParamsList(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public BDSBDHParamsList(IEncodable encodable) : base(encodable, info) {}

        // конструктор при закодировании
	    public BDSBDHParamsList(BDSParamsList bdsParamsList, BDHParamsList bdhParamsList)
            : base(info, bdsParamsList, bdhParamsList) {} 

	    public BDSParamsList BDSParamsList { get { return (BDSParamsList)this[0]; }} 
	    public BDHParamsList BDHParamsList { get { return (BDHParamsList)this[1]; }}
    
	    ///////////////////////////////////////////////////////////////////////////
	    // Таблица именованных параметров
	    ///////////////////////////////////////////////////////////////////////////
	    private static readonly Dictionary<String, BDSBDHParamsList> set = 
            new Dictionary<String, BDSBDHParamsList>(); 
	    static BDSBDHParamsList()
        {
		    set.Add(OID.stb11762_params3, new BDSBDHParamsList(
                BDSParamsList.Parameters(OID.stb11762_params3_bds), 
                BDHParamsList.Parameters(OID.stb11762_params3_bdh) 
            )); 
		    set.Add(OID.stb11762_params6, new BDSBDHParamsList(
                BDSParamsList.Parameters(OID.stb11762_params6_bds), 
                BDHParamsList.Parameters(OID.stb11762_params6_bdh) 
            )); 
		    set.Add(OID.stb11762_params10, new BDSBDHParamsList(
                BDSParamsList.Parameters(OID.stb11762_params10_bds), 
                BDHParamsList.Parameters(OID.stb11762_params10_bdh) 
            )); 
	    }
	    // получить именованные параметры
	    public static BDSBDHParamsList Parameters(string oid) { return set[oid]; } 
    }
}


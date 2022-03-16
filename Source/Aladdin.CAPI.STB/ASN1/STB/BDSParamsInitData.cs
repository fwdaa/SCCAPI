using System; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.STB
{
    ///////////////////////////////////////////////////////////////////////////////
    //	BDSParamsInitData ::= SEQUENCE {
    //		bdsPrmsInitZSequence OCTET STRING,
    //		bdsPrmsInitDSequence OCTET STRING,
    //		bdsPrmsInitRSequence OCTET STRING,
    //		bdsPrmsInitDValue INTEGER
    //	}
    ///////////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class BDSParamsInitData : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 
        
		    new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<Integer    >().Factory(), Cast.N) 
	    }; 
		// конструктор при сериализации
        protected BDSParamsInitData(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public BDSParamsInitData(IEncodable encodable) : base(encodable, info) {}  
    
	    // конструктор при закодировании
	    public BDSParamsInitData(OctetString bdsPrmsInitZSequence, 
            OctetString bdsPrmsInitDSequence, OctetString bdsPrmsInitRSequence, 
            Integer bdsPrmsInitDValue) : base(info, bdsPrmsInitZSequence, 
            bdsPrmsInitDSequence, bdsPrmsInitRSequence, bdsPrmsInitDValue) {} 

	    public OctetString BDSPrmsInitZSequence { get { return (OctetString)this[0]; }}
	    public OctetString BDSPrmsInitDSequence { get { return (OctetString)this[1]; }} 
	    public OctetString BDSPrmsInitRSequence { get { return (OctetString)this[2]; }} 
	    public Integer     BDSPrmsInitDValue    { get { return (Integer	   )this[3]; }} 
    }
}

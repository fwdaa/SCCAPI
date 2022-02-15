namespace Aladdin.ASN1.STB
{
    ///////////////////////////////////////////////////////////////////////////////
    // BDSKeyValue ::= INTEGER
    // BDSBDHKeyValue ::= SEQUENCE {
    // 		bdsKey INTEGER,
    // 		bdhKey INTEGER
    // 	}
    ///////////////////////////////////////////////////////////////////////////////
    public class BDSBDHKeyValue : Sequence 
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 
        
		    new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N),
		    new ObjectInfo(new ObjectCreator<Integer>().Factory(), Cast.N) 
	    }; 
	    // конструктор при раскодировании
	    public BDSBDHKeyValue(IEncodable encodable) : base(encodable, info) {}  
    
	    // конструктор при закодировании
	    public BDSBDHKeyValue(Integer bdsKey, Integer bdhKey) : base(info, bdsKey, bdhKey) {} 

	    public Integer BDSKey { get { return (Integer)this[0]; }}
	    public Integer BDHKey { get { return (Integer)this[1]; }} 
    }
}

namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // FieldElement ::= OCTET STRING
    // Curve ::= SEQUENCE {
    //      a FieldElement,
    //      b FieldElement,
    //      seed BIT STRING OPTIONAL
    // }
    ////////////////////////////////////////////////////////////////////////////////
    public class Curve : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 
        
		    new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<OctetString>().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<BitString  >().Factory(), Cast.O), 
	    }; 
	    // конструктор при раскодировании
	    public Curve(IEncodable encodable) : base(encodable, info) {} 
    
	    // конструктор при закодировании
	    public Curve(OctetString a, OctetString b, BitString seed) : base(info, a, b, seed) {}

        public OctetString A    { get { return (OctetString)this[0]; }}
	    public OctetString B    { get { return (OctetString)this[1]; }} 
	    public BitString   Seed { get { return (BitString  )this[2]; }}
    }
}

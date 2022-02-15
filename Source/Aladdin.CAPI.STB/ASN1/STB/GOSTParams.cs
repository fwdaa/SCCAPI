namespace Aladdin.ASN1.STB
{
    ////////////////////////////////////////////////////////////////////////////////
    // IV ::= OCTET STRING (SIZE(8))
    // GOSTParams ::= SEQUENCE {
    // 	iv IV,
    // 	sblock SBlock OPTIONAL
    // }
    ////////////////////////////////////////////////////////////////////////////////
    public class GOSTParams : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

            new ObjectInfo(new ObjectCreator<OctetString>().Factory(8, 8), Cast.N), 
		    new ObjectInfo(new ChoiceCreator<SBlock     >().Factory(    ), Cast.O) 
	    }; 
	    // конструктор при раскодировании
	    public GOSTParams(IEncodable encodable) : base(encodable, info) {} 
    
	    // конструктор при закодировании
	    public GOSTParams(OctetString iv, IEncodable sblock) : base(info, iv, sblock) {}

	    public OctetString IV     { get { return (OctetString)this[0]; }}
	    public IEncodable  SBlock { get { return              this[1]; }}
    }
}

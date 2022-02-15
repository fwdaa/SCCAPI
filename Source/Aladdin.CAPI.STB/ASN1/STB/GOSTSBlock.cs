namespace Aladdin.ASN1.STB
{
    ////////////////////////////////////////////////////////////////////////////////
    // GOSTSBlock ::= SEQUENCE {
    // 	sblock SBlock OPTIONAL
    // }
    ////////////////////////////////////////////////////////////////////////////////
    public class GOSTSBlock : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

		    new ObjectInfo(new ChoiceCreator<SBlock>().Factory(), Cast.O), 
	    }; 
	    // конструктор при раскодировании
	    public GOSTSBlock(IEncodable encodable) : base(encodable, info) {} 
    
	    // конструктор при закодировании
	    public GOSTSBlock(OctetString sblock) : base(info, sblock) {}
    
	    // конструктор при закодировании
	    public GOSTSBlock(ObjectIdentifier sblock) : base(info, sblock) {}
    
	    public IEncodable SBlock { get { return this[0]; }}
    }
}

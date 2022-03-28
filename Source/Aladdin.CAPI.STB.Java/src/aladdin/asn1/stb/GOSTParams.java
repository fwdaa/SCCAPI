package aladdin.asn1.stb;
import aladdin.asn1.*; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// IV ::= OCTET STRING (SIZE(8))
// GOSTParams ::= SEQUENCE {
// 	iv IV,
// 	sblock SBlock OPTIONAL
// }
////////////////////////////////////////////////////////////////////////////////
public final class GOSTParams extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -3352204911057778739L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

        new ObjectInfo(new ObjectCreator(OctetString.class).factory(8, 8), Cast.N), 
		new ObjectInfo(new ChoiceCreator(SBlock     .class).factory(    ), Cast.O), 
	}; 
	// конструктор при раскодировании
	public GOSTParams(IEncodable encodable) throws IOException { super(encodable, info); } 
    
	// конструктор при закодировании
	public GOSTParams(OctetString iv, IEncodable sblock) 
	{
		super(info, iv, sblock); 
	}  
	public final OctetString iv    () { return (OctetString)get(0); } 
	public final IEncodable	 sblock() { return              get(1); }
}

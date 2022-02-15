package aladdin.asn1.stb;
import aladdin.asn1.*; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// GOSTParams ::= SEQUENCE {
// 	sblock SBlock OPTIONAL
// }
////////////////////////////////////////////////////////////////////////////////
public final class GOSTSBlock extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ChoiceCreator(SBlock.class).factory(), Cast.O), 
	}; 
	// конструктор при раскодировании
	public GOSTSBlock(IEncodable encodable) throws IOException { super(encodable, info); } 
    
	// конструктор при закодировании
	public GOSTSBlock(OctetString sblock) { super(info, sblock); }
    
	// конструктор при закодировании
	public GOSTSBlock(ObjectIdentifier sblock) { super(info, sblock); }
    
	public final IEncodable	sblock() { return get(0); }
}

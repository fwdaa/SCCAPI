package aladdin.asn1.ansi.x962;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

////////////////////////////////////////////////////////////////////////////////
// Characteristic-two ::= SEQUENCE {
//      m           INTEGER,                      -- Field size 2^m
//      basis       OBJECT IDENTIFIER,
//      parameters  ANY DEFINED BY basis 
// }
////////////////////////////////////////////////////////////////////////////////
public final class CharacteristicTwo extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -2861765226321137600L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer         .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(ObjectIdentifier.class).factory(), Cast.N), 
		new ObjectInfo(    ImplicitCreator				        .factory  , Cast.N), 
	}; 
	// конструктор при раскодировании
	public CharacteristicTwo(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public CharacteristicTwo(Integer m, ObjectIdentifier basis, IEncodable parameters) 
    { 
        super(info, m, basis, parameters); 
    }
	public final Integer          m         () { return (Integer         )get(0); }
	public final ObjectIdentifier basis     () { return (ObjectIdentifier)get(1); }
	public final IEncodable       parameters() { return                   get(2); }
}

package aladdin.asn1.ansi.x962;
import aladdin.asn1.*; 

////////////////////////////////////////////////////////////////////////////////
// ECCSupplements ::= CHOICE {
//      namedMultiples      [0] EXPLICIT NamedMultiples,
//      specifiedMultiples  [1] EXPLICIT SpecifiedMultiples
// }
////////////////////////////////////////////////////////////////////////////////
public final class ECCSupplements extends Choice
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(NamedMultiples    .class).factory(), Cast.E, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(SpecifiedMultiples.class).factory(), Cast.E, Tag.context(1)) 
	}; 
	// конструктор
	public ECCSupplements() { super(info); } 
}

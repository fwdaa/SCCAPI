package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 
import java.io.*; 

//	PersonalName ::= SET {
//		surname				 [0] IMPLICIT PrintableString (SIZE (1..ub-surname-length)),
//		given-name			 [1] IMPLICIT PrintableString (SIZE (1..ub-given-name-length))			 OPTIONAL,
//		initials			 [2] IMPLICIT PrintableString (SIZE (1..ub-initials-length))			 OPTIONAL,
//		generation-qualifier [3] IMPLICIT PrintableString (SIZE (1..ub-generation-qualifier-length)) OPTIONAL 
//	}
//	ub-surname-length				INTEGER ::= 40
//	ub-given-name-length			INTEGER ::= 16
//	ub-initials-length				INTEGER ::= 5
//	ub-generation-qualifier-length	INTEGER ::= 3

public final class PersonalName extends Set<PrintableString>
{
    private static final long serialVersionUID = -723388449814373758L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(PrintableString.class).factory(1, 40), Cast.N, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(PrintableString.class).factory(1, 16), Cast.O, Tag.context(1)), 
		new ObjectInfo(new ObjectCreator(PrintableString.class).factory(1,  5), Cast.O, Tag.context(2)), 
		new ObjectInfo(new ObjectCreator(PrintableString.class).factory(1,  3), Cast.O, Tag.context(3)), 
	}; 
	// конструктор при раскодировании
	public PersonalName(IEncodable encodable) throws IOException { super(encodable, info); }
	
	// конструктор при закодировании
	public PersonalName(PrintableString surname, PrintableString givenName,
		PrintableString initials, PrintableString generationQualifier) 
	{
		super(info, surname, givenName, initials, generationQualifier); 
	}
	public final PrintableString surname			() { return get(0); }
	public final PrintableString givenName          () { return get(1); }
	public final PrintableString initials			() { return get(2); }
	public final PrintableString generationQualifier() { return get(3); }
}

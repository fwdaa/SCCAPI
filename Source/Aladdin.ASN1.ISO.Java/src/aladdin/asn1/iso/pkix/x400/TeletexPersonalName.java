package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 
import java.io.*; 

//	TeletexPersonalName ::= SET {
//		surname				 [0] IMPLICIT TeletexString (SIZE (1..ub-surname-length)),
//		given-name			 [1] IMPLICIT TeletexString (SIZE (1..ub-given-name-length))			OPTIONAL,
//		initials			 [2] IMPLICIT TeletexString (SIZE (1..ub-initials-length))				OPTIONAL,
//		generation-qualifier [3] IMPLICIT TeletexString (SIZE (1..ub-generation-qualifier-length))	OPTIONAL 
//	}
//	ub-surname-length				INTEGER ::= 40
//	ub-given-name-length			INTEGER ::= 16
//	ub-initials-length				INTEGER ::= 5
//	ub-generation-qualifier-length	INTEGER ::= 3

public final class TeletexPersonalName extends Set<TeletexString>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(TeletexString.class).factory(1, 40), Cast.N, Tag.context(0)), 
		new ObjectInfo(new ObjectCreator(TeletexString.class).factory(1, 16), Cast.O, Tag.context(1)), 
		new ObjectInfo(new ObjectCreator(TeletexString.class).factory(1,  5), Cast.O, Tag.context(2)), 
		new ObjectInfo(new ObjectCreator(TeletexString.class).factory(1,  3), Cast.O, Tag.context(3)), 
	}; 
	// конструктор при раскодировании
	public TeletexPersonalName(IEncodable encodable) throws IOException { super(encodable, info); }
	
	// конструктор при закодировании
	public TeletexPersonalName(TeletexString surname, TeletexString givenName,
		TeletexString initials, TeletexString generationQualifier) 
	{
		super(info, surname, givenName, initials, generationQualifier); 
	}
	public final TeletexString surname              () { return get(0); }
	public final TeletexString givenName		    () { return get(1); }
	public final TeletexString initials             () { return get(2); }
	public final TeletexString generationQualifier  () { return get(3); }
}

package aladdin.asn1.iso;
import aladdin.asn1.*; 
import java.io.*; 

// RevocationInfoChoices ::= SET OF RevocationInfoChoice

public final class RevocationInfoChoices extends Set<IEncodable>
{
	// конструктор при раскодировании
	public RevocationInfoChoices(IEncodable encodable) throws IOException 
	{
		super(new ChoiceCreator(RevocationInfoChoice.class).factory(), encodable); 
	} 
	// конструктор при закодировании
	public RevocationInfoChoices(Sequence<?>... values) 
	{
		super(new ChoiceCreator(RevocationInfoChoice.class).factory(), values); 
	} 
}

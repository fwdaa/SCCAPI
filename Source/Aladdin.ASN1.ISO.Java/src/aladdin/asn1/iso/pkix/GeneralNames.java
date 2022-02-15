package aladdin.asn1.iso.pkix;
import aladdin.asn1.*; 
import java.io.*;

// GeneralNames ::= SEQUENCE OF GeneralName

public final class GeneralNames extends Sequence<IEncodable>
{
	// конструктор при раскодировании
	public GeneralNames(IEncodable encodable) throws IOException 
	{
		super(new ChoiceCreator(GeneralName.class).factory(), encodable);
	}
	// конструктор при закодировании
	public GeneralNames(IEncodable... values) 
	{
		super(new ChoiceCreator(GeneralName.class).factory(), values); 
	}
}

package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 
import java.io.*; 

//	PDSParameter ::= SET {
//		printable-string PrintableString (SIZE(1..ub-pds-parameter-length)) OPTIONAL,
//		teletex-string	 TeletexString	 (SIZE(1..ub-pds-parameter-length)) OPTIONAL 
//	}
//  ub-pds-parameter-length INTEGER ::= 30

public final class PDSParameter extends Set<IEncodable>
{
    private static final long serialVersionUID = -6355771553128635887L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(PrintableString.class).factory(1, 30), Cast.O), 
		new ObjectInfo(new ObjectCreator(TeletexString  .class).factory(1, 30), Cast.O), 
	}; 
	// конструктор при раскодировании
	public PDSParameter(IEncodable encodable) throws IOException { super(encodable, info); }  
	
	// конструктор при закодировании
	public PDSParameter(PrintableString printableString, TeletexString teletexString) 
	{
		super(info, printableString, teletexString); 
	}
	public final PrintableString printableString() { return (PrintableString)get(0); }
	public final TeletexString   teletexString  () { return (TeletexString  )get(1); }
}

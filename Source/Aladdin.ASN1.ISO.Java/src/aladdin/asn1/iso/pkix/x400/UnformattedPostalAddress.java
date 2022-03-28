package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 
import java.io.*; 

//	UnformattedPostalAddress ::= SET {
//		printable-address	PrintableAddress OPTIONAL,
//		teletex-string		TeletexString (SIZE (1..ub-unformatted-address-length)) OPTIONAL 
//	}
//	ub-unformatted-address-length	INTEGER ::= 180

public final class UnformattedPostalAddress extends Set<IEncodable>
{
    private static final long serialVersionUID = -7797337612740386358L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(PrintableAddress   .class).factory(      ), Cast.O), 
		new ObjectInfo(new ObjectCreator(TeletexString      .class).factory(1, 180), Cast.O), 
	}; 
	// конструктор при раскодировании
	public UnformattedPostalAddress(IEncodable encodable) throws IOException { super(encodable, info); } 
	
	// конструктор при закодировании
	public UnformattedPostalAddress(PrintableAddress printableAddress, 
		TeletexString teletexString) 
	{
		super(info, printableAddress, teletexString); 
	}
	public final PrintableAddress   printableAddress() { return (PrintableAddress   )get(0); }
	public final TeletexString      teletexString   () { return (TeletexString      )get(1); }
}

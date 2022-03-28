package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*;
import java.io.*; 

// PrintableAddress	::= SEQUENCE SIZE (1..ub-pds-physical-address-lines) OF PrintableString (SIZE (1..ub-pds-parameter-length))

//  ub-pds-parameter-length			INTEGER ::= 30
//	ub-pds-physical-address-lines	INTEGER ::= 6

public final class PrintableAddress extends Sequence<PrintableString>
{
    private static final long serialVersionUID = 1377517232132180406L;
    
	// конструктор при раскодировании
	public PrintableAddress(IEncodable encodable) throws IOException
	{
		 super(PrintableString.class, encodable); 
		
		// проверить корректность
		if (size() <= 0 || size() > 6) throw new IOException(); 

		// для каждого элемента
		for (PrintableString obj : this) 
		{
			// проверить корректность элемента
			PrintableString.validate(obj, false, 1, 30);
		} 
	} 
	// конструктор при закодировании
	public PrintableAddress(PrintableString... values) 
	{
		 super(PrintableString.class, values); 
		
		// проверить корректность
		if (size() <= 0 || size() > 6) throw new IllegalArgumentException(); 

		// для каждого элемента
		for (PrintableString obj : this) 
		{
			// проверить корректность элемента
			try { PrintableString.validate(obj, true, 1, 30); }

            // пропустить невозможную ошибку
            catch (IOException e) { throw new RuntimeException(e); } 
		} 
	} 
}

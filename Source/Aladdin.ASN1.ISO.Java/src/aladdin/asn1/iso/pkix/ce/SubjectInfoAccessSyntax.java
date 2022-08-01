package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*;
import java.io.*;

// SubjectInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription

public final class SubjectInfoAccessSyntax extends Sequence<AccessDescription>
{
    // private static final long serialVersionUID = -8178727199716067465L;
    
	// конструктор при раскодировании
	public SubjectInfoAccessSyntax(IEncodable encodable) throws IOException 
	{
		super(AccessDescription.class, encodable); 
        
		// проверить корректность
        if (size() == 0) throw new IOException(); 
	}
	// конструктор при закодировании
	public SubjectInfoAccessSyntax(AccessDescription... values) 
	{
		super(AccessDescription.class, values); 
        
		// проверить корректность
		if (size() == 0) throw new IllegalArgumentException(); 
	}
}

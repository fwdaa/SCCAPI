package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*;
import java.io.*;

// AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription

public final class AuthorityInfoAccessSyntax extends Sequence<AccessDescription>
{
    // private static final long serialVersionUID = -8178727199716067465L;
    
	// конструктор при раскодировании
	public AuthorityInfoAccessSyntax(IEncodable encodable) throws IOException 
	{
		super(AccessDescription.class, encodable); 
        
		// проверить корректность
        if (size() == 0) throw new IOException(); 
	}
	// конструктор при закодировании
	public AuthorityInfoAccessSyntax(AccessDescription... values) 
	{
		super(AccessDescription.class, values); 
        
		// проверить корректность
		if (size() == 0) throw new IllegalArgumentException(); 
	}
}

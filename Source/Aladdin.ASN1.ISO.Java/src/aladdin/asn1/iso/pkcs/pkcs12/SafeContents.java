package aladdin.asn1.iso.pkcs.pkcs12;
import aladdin.asn1.*;
import java.io.*; 

// SafeContents ::= SEQUENCE OF SafeBag

public final class SafeContents extends Sequence<SafeBag>
{
    private static final long serialVersionUID = -7514215561210347671L;
    
	// конструктор при раскодировании
	public SafeContents(IEncodable encodable) throws IOException
	{
		super(SafeBag.class, encodable); 	
	} 
	// конструктор при закодировании
	public SafeContents(SafeBag... values) 
	{
		super(SafeBag.class, values); 	
	} 
}



package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*; 
import java.io.*;

// ExtKeyUsageSyntax ::= SEQUENCE OF OBJECT IDENTIFIER

public final class ExtKeyUsageSyntax extends Sequence<ObjectIdentifier>
{
    private static final long serialVersionUID = 3395090662622544339L;
    
	// конструктор при раскодировании
	public ExtKeyUsageSyntax(IEncodable encodable) throws IOException 
	{
		super(ObjectIdentifier.class, encodable); 
	}
	// конструктор при закодировании
	public ExtKeyUsageSyntax(ObjectIdentifier... values) 
	{
		super(ObjectIdentifier.class, values); 
	}
}

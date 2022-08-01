package aladdin.asn1.iso.ocsp;
import aladdin.asn1.*;
import aladdin.asn1.iso.pkix.*;
import aladdin.asn1.iso.pkix.ce.*;
import java.io.*;

// ServiceLocator ::= SEQUENCE {
//     issuer    Name,
//     locator   AuthorityInfoAccessSyntax 
// }

public class ServiceLocator extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ChoiceCreator(Name	                  .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(AuthorityInfoAccessSyntax.class).factory(), Cast.N), 
	}; 
	// конструктор при раскодировании
	public ServiceLocator(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public ServiceLocator(IEncodable issuer, AuthorityInfoAccessSyntax locator) 
	{ 
		super(info, issuer, locator); 
	}
	public final IEncodable                 issuer () { return (IEncodable               )get(0); } 
	public final AuthorityInfoAccessSyntax  locator() { return (AuthorityInfoAccessSyntax)get(1); }
}

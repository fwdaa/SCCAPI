package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 
import java.io.*; 

//	ORAddress ::= SEQUENCE {
//		built-in-standard-attributes		BuiltInStandardAttributes,
//		built-in-domain-defined-attributes	BuiltInDomainDefinedAttributes	OPTIONAL,
//		extension-attributes				ExtensionAttributes				OPTIONAL 
//	}

public final class OrAddress extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -2516062739200758547L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(BuiltInStandardAttributes      .class).factory(), Cast.N), 
		new ObjectInfo(new ObjectCreator(BuiltInDomainDefinedAttributes .class).factory(), Cast.O), 
		new ObjectInfo(new ObjectCreator(ExtensionAttributes			.class).factory(), Cast.O), 
	}; 
	// конструктор при раскодировании
	public OrAddress(IEncodable encodable) throws IOException { super(encodable, info); }

	// конструктор при закодировании
	public OrAddress(BuiltInStandardAttributes builtInStandardAttributes,	
		BuiltInDomainDefinedAttributes builtInDomainDefinedAttributes, 
		ExtensionAttributes extensionAttributes) 
	{
		super(info, builtInStandardAttributes, builtInDomainDefinedAttributes, extensionAttributes); 
	} 
	public final BuiltInStandardAttributes      builtInStandardAttributes		() { return (BuiltInStandardAttributes     )get(0); }
	public final BuiltInDomainDefinedAttributes builtInDomainDefinedAttributes  () { return (BuiltInDomainDefinedAttributes)get(1); }
	public final ExtensionAttributes			extensionAttributes             () { return (ExtensionAttributes           )get(2); }
}

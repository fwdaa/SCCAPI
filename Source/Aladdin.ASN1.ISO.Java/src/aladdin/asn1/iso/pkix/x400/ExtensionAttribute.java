package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import java.io.*; 

//	ExtensionAttribute ::=  SEQUENCE {
//		extension-attribute-type  [0] IMPLICIT INTEGER (0..ub-extension-attributes),
//		extension-attribute-value [1] EXPLICIT ANY DEFINED BY extension-attribute-type 
//	}
//	ub-extension-attributes INTEGER ::= 256

public final class ExtensionAttribute extends Sequence<IEncodable>
{
    private static final long serialVersionUID = -8147404776328436065L;
    
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(Integer.class).factory(0, 256),	Cast.N, Tag.context(0)), 
		new ObjectInfo(    ImplicitCreator		       .factory        ,	Cast.E, Tag.context(1)), 
	}; 
	// раскодировать атрибут
	private static IEncodable DecodeAttribute(int type, IEncodable encodable) throws IOException
	{
		switch (type) 
		{
		// раскодировать значение атрибута
		case OID.EXT_AT_COMMON_NAME:									return new ObjectCreator(PrintableString			.class).factory(1,  64).decode(encodable); 
		case OID.EXT_AT_TELETEX_COMMON_NAME:							return new ObjectCreator(TeletexString				.class).factory(1,  64).decode(encodable); 
		case OID.EXT_AT_TELETEX_ORGANIZATION_NAME:						return new ObjectCreator(TeletexString				.class).factory(1,  64).decode(encodable); 
		case OID.EXT_AT_TELETEX_PERSONAL_NAME:							return new ObjectCreator(TeletexPersonalName			.class).factory(      ).decode(encodable); 
		case OID.EXT_AT_TELETEX_ORGANIZATIONAL_UNIT_NAMES:				return new ObjectCreator(TeletexOrganizationalUnitNames	.class).factory(      ).decode(encodable); 
		case OID.EXT_AT_TELETEX_DOMAIN_DEFINED_ATTRIBUTES: 				return new ObjectCreator(TeletexDomainDefinedAttributes	.class).factory(      ).decode(encodable); 
		case OID.EXT_AT_PDS_NAME:										return new ObjectCreator(PrintableString			.class).factory(1,  16).decode(encodable);
		case OID.EXT_AT_PHYSICAL_DELIVERY_COUNTRY_NAME:					return new ChoiceCreator(PhysicalDeliveryCountryName	.class).factory(      ).decode(encodable);			 
		case OID.EXT_AT_POSTAL_CODE: 									return new ChoiceCreator(PostalCode						.class).factory(      ).decode(encodable);							 
		case OID.EXT_AT_PHYSICAL_DELIVERY_OFFICE_NAME: 					return new ObjectCreator(PDSParameter					.class).factory(      ).decode(encodable);			 
		case OID.EXT_AT_PHYSICAL_DELIVERY_OFFICE_NUMBER: 				return new ObjectCreator(PDSParameter					.class).factory(      ).decode(encodable);			 
		case OID.EXT_AT_EXTENSION_OR_ADDRESS_COMPONENTS: 				return new ObjectCreator(PDSParameter					.class).factory(      ).decode(encodable);			
		case OID.EXT_AT_PHYSICAL_DELIVERY_PERSONAL_NAME: 				return new ObjectCreator(PDSParameter					.class).factory(      ).decode(encodable);			 
		case OID.EXT_AT_PHYSICAL_DELIVERY_ORGANIZATION_NAME: 			return new ObjectCreator(PDSParameter					.class).factory(      ).decode(encodable);		
		case OID.EXT_AT_EXTENSION_PHYSICAL_DELIVERY_ADDRESS_COMPONENTS: return new ObjectCreator(PDSParameter					.class).factory(      ).decode(encodable);
		case OID.EXT_AT_UNFORMATTED_POSTAL_ADDRESS: 					return new ObjectCreator(UnformattedPostalAddress		.class).factory(      ).decode(encodable);	
		case OID.EXT_AT_STREET_ADDRESS: 								return new ObjectCreator(PDSParameter					.class).factory(      ).decode(encodable);			 
		case OID.EXT_AT_POST_OFFICE_BOX_ADDRESS: 						return new ObjectCreator(PDSParameter					.class).factory(      ).decode(encodable);		
		case OID.EXT_AT_POSTE_RESTANTE_ADDRESS: 						return new ObjectCreator(PDSParameter					.class).factory(      ).decode(encodable);		
		case OID.EXT_AT_UNIQUE_POSTAL_NAME: 							return new ObjectCreator(PDSParameter					.class).factory(      ).decode(encodable);			
		case OID.EXT_AT_LOCAL_POSTAL_ATTRIBUTES: 						return new ObjectCreator(PDSParameter                   .class).factory(      ).decode(encodable);	 
		case OID.EXT_AT_EXTENDED_NETWORK_ADDRESS: 						return new ChoiceCreator(ExtendedNetworkAddress         .class).factory(      ).decode(encodable);	
		case OID.EXT_AT_TERMINAL_TYPE: 									return new ObjectCreator(Integer                    .class).factory(0, 256).decode(encodable); 
		}
		// неизвестный тип объекта
		return encodable;	 
	}
	// конструктор при раскодировании
	public ExtensionAttribute(IEncodable encodable) throws IOException { super(encodable, info); 
	
		// раскодировать атрибут
		put(1, DecodeAttribute(extensionAttributeType().value().intValue(), extensionAttributeValue()));
	}
	// конструктор при закодировании
	public ExtensionAttribute(Integer extensionAttributeType, IEncodable extensionAttributeValue) 
	{
		super(info, extensionAttributeType, extensionAttributeValue); 
				
		// раскодировать атрибут
		try { put(1, DecodeAttribute(extensionAttributeType.value().intValue(), extensionAttributeValue)); } 
		
		// обработать возможное исключение
		catch (IOException e) { throw new IllegalArgumentException(); }
	} 
	public final Integer      extensionAttributeType () { return (Integer)get(0); }
	public final IEncodable   extensionAttributeValue() { return          get(1); }
}

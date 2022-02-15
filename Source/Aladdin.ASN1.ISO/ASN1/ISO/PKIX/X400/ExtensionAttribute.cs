using System;

//	ExtensionAttribute ::=  SEQUENCE {
//		extension-attribute-type  [0] IMPLICIT INTEGER (0..ub-extension-attributes),
//		extension-attribute-value [1] EXPLICIT ANY DEFINED BY extension-attribute-type 
//	}
//	ub-extension-attributes INTEGER ::= 256

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	public class ExtensionAttribute : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<Integer>().Factory(0, 256), Cast.N, Tag.Context(0)), 
			new ObjectInfo(    ImplicitCreator		   .Factory        , Cast.E, Tag.Context(1)), 
		}; 
		// раскодировать атрибут
		private static IEncodable DecodeAttribute(int type, IEncodable encodable)
		{
			switch (type) 
			{
			// раскодировать значение атрибута
			case OID.ext_at_common_name:									return new ObjectCreator<PrintableString				>().Factory(1,  64).Decode(encodable); 
			case OID.ext_at_teletex_common_name:							return new ObjectCreator<TeletexString					>().Factory(1,  64).Decode(encodable); 
			case OID.ext_at_teletex_organization_name:						return new ObjectCreator<TeletexString					>().Factory(1,  64).Decode(encodable); 
			case OID.ext_at_teletex_personal_name:							return new ObjectCreator<TeletexPersonalName			>().Factory(      ).Decode(encodable); 
			case OID.ext_at_teletex_organizational_unit_names:				return new ObjectCreator<TeletexOrganizationalUnitNames	>().Factory(      ).Decode(encodable); 
			case OID.ext_at_teletex_domain_defined_attributes: 				return new ObjectCreator<TeletexDomainDefinedAttributes	>().Factory(      ).Decode(encodable); 
			case OID.ext_at_pds_name:										return new ObjectCreator<PrintableString				>().Factory(1,  16).Decode(encodable);
			case OID.ext_at_physical_delivery_country_name:					return new ChoiceCreator<PhysicalDeliveryCountryName	>().Factory(      ).Decode(encodable);			 
			case OID.ext_at_postal_code: 									return new ChoiceCreator<PostalCode						>().Factory(      ).Decode(encodable);							 
			case OID.ext_at_physical_delivery_office_name: 					return new ObjectCreator<PDSParameter					>().Factory(      ).Decode(encodable);			 
			case OID.ext_at_physical_delivery_office_number: 				return new ObjectCreator<PDSParameter					>().Factory(      ).Decode(encodable);			 
			case OID.ext_at_extension_OR_address_components: 				return new ObjectCreator<PDSParameter					>().Factory(      ).Decode(encodable);			
			case OID.ext_at_physical_delivery_personal_name: 				return new ObjectCreator<PDSParameter					>().Factory(      ).Decode(encodable);			 
			case OID.ext_at_physical_delivery_organization_name: 			return new ObjectCreator<PDSParameter					>().Factory(      ).Decode(encodable);		
			case OID.ext_at_extension_physical_delivery_address_components: return new ObjectCreator<PDSParameter					>().Factory(      ).Decode(encodable);
			case OID.ext_at_unformatted_postal_address: 					return new ObjectCreator<UnformattedPostalAddress		>().Factory(      ).Decode(encodable);	
			case OID.ext_at_street_address: 								return new ObjectCreator<PDSParameter					>().Factory(      ).Decode(encodable);			 
			case OID.ext_at_post_office_box_address: 						return new ObjectCreator<PDSParameter					>().Factory(      ).Decode(encodable);		
			case OID.ext_at_poste_restante_address: 						return new ObjectCreator<PDSParameter					>().Factory(      ).Decode(encodable);		
			case OID.ext_at_unique_postal_name: 							return new ObjectCreator<PDSParameter					>().Factory(      ).Decode(encodable);			
			case OID.ext_at_local_postal_attributes: 						return new ObjectCreator<PDSParameter					>().Factory(      ).Decode(encodable);	 
			case OID.ext_at_extended_network_address: 						return new ChoiceCreator<ExtendedNetworkAddress			>().Factory(      ).Decode(encodable);	
			case OID.ext_at_terminal_type: 									return new ObjectCreator<Integer						>().Factory(0, 256).Decode(encodable); 
			}
			// неизвестный тип объекта
			return encodable;	 
		}
		// конструктор при раскодировании
		public ExtensionAttribute(IEncodable encodable) : base(encodable, info) 
		{
			// раскодировать атрибут
			this[1] = DecodeAttribute(ExtensionAttributeType.Value.IntValue, ExtensionAttributeValue);
		}
		// конструктор при закодировании
		public ExtensionAttribute(Integer extensionAttributeType, IEncodable extensionAttributeValue) :
			base(info, extensionAttributeType, extensionAttributeValue) 
		{
			// раскодировать атрибут
			this[1] = DecodeAttribute(ExtensionAttributeType.Value.IntValue, ExtensionAttributeValue);
		} 
		public Integer	  ExtensionAttributeType  { get { return (Integer )this[0];	} }
		public IEncodable ExtensionAttributeValue { get { return           this[1];	} }
	}
}

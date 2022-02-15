using System;

// BuiltInStandardAttributes ::= SEQUENCE {
//		country-name							CountryName					OPTIONAL,
//		administration-domain-name				AdministrationDomainName	OPTIONAL,
//		network-address            [0] IMPLICIT NumericString				OPTIONAL,
//		terminal-identifier        [1] IMPLICIT PrintableString				OPTIONAL,
//		private-domain-name        [2] EXPLICIT PrivateDomainName			OPTIONAL,
//		organization-name          [3] IMPLICIT PrintableString				OPTIONAL,
//		numeric-user-identifier    [4] IMPLICIT NumericString				OPTIONAL,
//		personal-name              [5] IMPLICIT PersonalName				OPTIONAL,
//		organizational-unit-names  [6] IMPLICIT OrganizationalUnitNames		OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	public class BuiltInStandardAttributes : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<CountryName				>().Factory(     ),	Cast.O,	 Tag.Any		), 
			new ObjectInfo(new ObjectCreator<AdministrationDomainName	>().Factory(     ),	Cast.O,	 Tag.Any		), 
			new ObjectInfo(new ObjectCreator<NumericString			    >().Factory(1, 16),	Cast.O,	 Tag.Context(0)	), 
			new ObjectInfo(new ObjectCreator<PrintableString			>().Factory(1, 24),	Cast.O,	 Tag.Context(1)	), 
			new ObjectInfo(new ChoiceCreator<PrivateDomainName		    >().Factory(     ),	Cast.EO, Tag.Context(2)	), 
			new ObjectInfo(new ObjectCreator<PrintableString			>().Factory(1, 64),	Cast.O,	 Tag.Context(3)	), 
			new ObjectInfo(new ObjectCreator<NumericString			    >().Factory(1, 32),	Cast.O,	 Tag.Context(4)	), 
			new ObjectInfo(new ObjectCreator<PersonalName				>().Factory(     ),	Cast.O,	 Tag.Context(5)	), 
			new ObjectInfo(new ObjectCreator<OrganizationalUnitNames	>().Factory(     ),	Cast.O,	 Tag.Context(6)	), 
		}; 
		// конструктор при раскодировании
		public BuiltInStandardAttributes(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public BuiltInStandardAttributes(OctetString countryName, 
			OctetString administrationDomainName, NumericString networkAddress, 
			PrintableString terminalIdentifier, OctetString privateDomainName,
			PrintableString organizationName, NumericString numericUserIdentifier, 
			PersonalName personalName, OrganizationalUnitNames organizationalUnitNames) : 
			base(info, countryName, administrationDomainName, networkAddress, 
			terminalIdentifier, privateDomainName, organizationName, 
			numericUserIdentifier, personalName, organizationalUnitNames) {}

		public OctetString				CountryName				 { get { return (OctetString            )this[0]; } }
		public OctetString				AdministrationDomainName { get { return (OctetString			)this[1]; } }
		public NumericString			NetworkAddress			 { get { return (NumericString	        )this[2]; } }
		public PrintableString			TerminalIdentifier		 { get { return (PrintableString	    )this[3]; } }
		public OctetString				PrivateDomainName		 { get { return (OctetString	        )this[4]; } }
		public PrintableString			OrganizationName		 { get { return (PrintableString        )this[5]; } }
		public NumericString			NumericUserIdentifier	 { get { return (NumericString			)this[6]; } }
		public PersonalName				PersonalName			 { get { return (PersonalName           )this[7]; } }
		public OrganizationalUnitNames	OrganizationalUnitNames	 { get { return (OrganizationalUnitNames)this[8]; } }
	}
}

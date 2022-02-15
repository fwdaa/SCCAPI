package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 
import java.io.*;

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

public class BuiltInStandardAttributes extends Sequence<IEncodable>
{
	// информация о структуре
	private static final ObjectInfo[] info = new ObjectInfo[] { 

		new ObjectInfo(new ObjectCreator(CountryName				.class).factory(     ),	Cast.O,	 Tag.ANY		), 
		new ObjectInfo(new ObjectCreator(AdministrationDomainName	.class).factory(     ),	Cast.O,	 Tag.ANY		), 
		new ObjectInfo(new ObjectCreator(NumericString              .class).factory(1, 16),	Cast.O,	 Tag.context(0)	), 
		new ObjectInfo(new ObjectCreator(PrintableString            .class).factory(1, 24),	Cast.O,	 Tag.context(1)	), 
		new ObjectInfo(new ChoiceCreator(PrivateDomainName          .class).factory(     ),	Cast.EO, Tag.context(2)	), 
		new ObjectInfo(new ObjectCreator(PrintableString            .class).factory(1, 64),	Cast.O,	 Tag.context(3)	), 
		new ObjectInfo(new ObjectCreator(NumericString              .class).factory(1, 32),	Cast.O,	 Tag.context(4)	), 
		new ObjectInfo(new ObjectCreator(PersonalName				.class).factory(     ),	Cast.O,	 Tag.context(5)	), 
		new ObjectInfo(new ObjectCreator(OrganizationalUnitNames	.class).factory(     ),	Cast.O,	 Tag.context(6)	), 
	}; 
	// конструктор при раскодировании
	public BuiltInStandardAttributes(IEncodable encodable) throws IOException { super(encodable, info); }
	
	// конструктор при закодировании
	public BuiltInStandardAttributes(OctetString countryName, 
		OctetString administrationDomainName, NumericString networkAddress, 
		PrintableString terminalIdentifier, OctetString privateDomainName, 
		PrintableString organizationName, NumericString numericUserIdentifier, 
		PersonalName personalName, OrganizationalUnitNames organizationalUnitNames) 
	{
		super(info, countryName, administrationDomainName, networkAddress, 
			terminalIdentifier, privateDomainName, organizationName, 
			numericUserIdentifier, personalName, organizationalUnitNames
		); 
	}
	public final OctetString                countryName				() { return (OctetString            )get(0); }
	public final OctetString                administrationDomainName() { return (OctetString            )get(1); }
	public final NumericString              networkAddress			() { return (NumericString          )get(2); }
	public final PrintableString            terminalIdentifier		() { return (PrintableString        )get(3); }
	public final OctetString                privateDomainName		() { return (OctetString            )get(4); }
	public final PrintableString            organizationName		() { return (PrintableString        )get(5); }
	public final NumericString              numericUserIdentifier	() { return (NumericString          )get(6); }
	public final PersonalName				personalName			() { return (PersonalName           )get(7); }
	public final OrganizationalUnitNames	organizationalUnitNames	() { return (OrganizationalUnitNames)get(8); }
}

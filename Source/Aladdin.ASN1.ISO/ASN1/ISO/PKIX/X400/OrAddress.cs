using System;

//	ORAddress ::= SEQUENCE {
//		built-in-standard-attributes		BuiltInStandardAttributes,
//		built-in-domain-defined-attributes	BuiltInDomainDefinedAttributes	OPTIONAL,
//		extension-attributes				ExtensionAttributes				OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	public class OrAddress : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<BuiltInStandardAttributes		>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<BuiltInDomainDefinedAttributes	>().Factory(), Cast.O), 
			new ObjectInfo(new ObjectCreator<ExtensionAttributes			>().Factory(), Cast.O), 
		}; 
		// конструктор при раскодировании
		public OrAddress(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public OrAddress(BuiltInStandardAttributes builtInStandardAttributes,	
			BuiltInDomainDefinedAttributes builtInDomainDefinedAttributes, 
			ExtensionAttributes extensionAttributes) : 
			base(info, builtInStandardAttributes, 
			builtInDomainDefinedAttributes, extensionAttributes) {} 

		public BuiltInStandardAttributes	  BuiltInStandardAttributes		 { get { return (BuiltInStandardAttributes     )this[0]; } }
		public BuiltInDomainDefinedAttributes BuiltInDomainDefinedAttributes { get { return (BuiltInDomainDefinedAttributes)this[1]; } }
		public ExtensionAttributes			  ExtensionAttributes			 { get { return (ExtensionAttributes           )this[2]; } }
	}
}

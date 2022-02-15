using System;

//	GeneralName ::= CHOICE {
//		otherName                 [0] IMPLICIT AnotherName,
//		rfc822Name                [1] IMPLICIT IA5String,
//		dNSName                   [2] IMPLICIT IA5String,
//		x400Address               [3] IMPLICIT ORAddress,
//		directoryName             [4] IMPLICIT Name,
//		ediPartyName              [5] IMPLICIT EDIPartyName,
//		uniformResourceIdentifier [6] IMPLICIT IA5String,
//		iPAddress                 [7] IMPLICIT OCTET STRING,
//		registeredID              [8] IMPLICIT OBJECT IDENTIFIER 
//	}

namespace Aladdin.ASN1.ISO.PKIX
{
	public class GeneralName : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(    ImplicitCreator				       .Factory  , Cast.N, Tag.Context(0)), 
			new ObjectInfo(new ObjectCreator<IA5String		    >().Factory(), Cast.N, Tag.Context(1)), 
			new ObjectInfo(new ObjectCreator<IA5String		    >().Factory(), Cast.N, Tag.Context(2)), 
			new ObjectInfo(new ObjectCreator<X400.OrAddress	    >().Factory(), Cast.N, Tag.Context(3)), 
			new ObjectInfo(new ChoiceCreator<Name	            >().Factory(), Cast.N, Tag.Context(4)), 
			new ObjectInfo(new ObjectCreator<EDIPartyName	    >().Factory(), Cast.N, Tag.Context(5)), 
			new ObjectInfo(new ObjectCreator<IA5String		    >().Factory(), Cast.N, Tag.Context(6)), 
			new ObjectInfo(new ObjectCreator<OctetString		>().Factory(), Cast.N, Tag.Context(7)), 
			new ObjectInfo(new ObjectCreator<ObjectIdentifier	>().Factory(), Cast.N, Tag.Context(8)), 
		}; 
		// конструктор
		public GeneralName() : base(info) {} 
	}
}

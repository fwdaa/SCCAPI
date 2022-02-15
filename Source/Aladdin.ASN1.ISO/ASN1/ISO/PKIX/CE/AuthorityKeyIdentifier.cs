using System;
using System.IO;

//	AuthorityKeyIdentifier ::= SEQUENCE {
//		keyIdentifier             [0] IMPLICIT OCTET STRING	OPTIONAL,
//		authorityCertIssuer       [1] IMPLICIT GeneralNames OPTIONAL,
//		authorityCertSerialNumber [2] IMPLICIT INTEGER		OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	public class AuthorityKeyIdentifier : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString	>().Factory(), Cast.O, Tag.Context(0)), 
			new ObjectInfo(new ObjectCreator<GeneralNames	>().Factory(), Cast.O, Tag.Context(1)), 
			new ObjectInfo(new ObjectCreator<Integer		>().Factory(), Cast.O, Tag.Context(2)), 
		}; 
		// конструктор при раскодировании
		public AuthorityKeyIdentifier(IEncodable encodable) : base(encodable, info) 
		{
			// проверить наличие элементов
			if (AuthorityCertIssuer == null && AuthorityCertSerialNumber != null) throw new InvalidDataException();
			if (AuthorityCertIssuer != null && AuthorityCertSerialNumber == null) throw new InvalidDataException();
		}
		// конструктор при закодировании
		public AuthorityKeyIdentifier(OctetString keyIdentifier, 
			GeneralNames authorityCertIssuer, Integer authorityCertSerialNumber) : 
			base(info, keyIdentifier, authorityCertIssuer, authorityCertSerialNumber)   
		{
			// проверить наличие элементов
			if (AuthorityCertIssuer == null && AuthorityCertSerialNumber != null) throw new ArgumentException();
			if (AuthorityCertIssuer != null && AuthorityCertSerialNumber == null) throw new ArgumentException();
		}
		public OctetString	KeyIdentifier				{ get { return (OctetString	)this[0]; }} 
		public GeneralNames AuthorityCertIssuer			{ get { return (GeneralNames)this[1]; }}
		public Integer		AuthorityCertSerialNumber	{ get { return (Integer		)this[2]; }}
	}
}

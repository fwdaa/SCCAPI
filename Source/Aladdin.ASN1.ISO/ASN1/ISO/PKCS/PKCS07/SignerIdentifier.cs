﻿using System;

//	SignerIdentifier ::= CHOICE {
//		issuerSerialNumber					 IssuerSerialNumber,
//		subjectKeyIdentifier	[0] IMPLICIT OCTET STRING
//	}

namespace Aladdin.ASN1.ISO.PKCS.PKCS7
{
	public class SignerIdentifier : Choice
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<PKIX.IssuerSerialNumber>().Factory(), Cast.N, Tag.Any			), 
			new ObjectInfo(new ObjectCreator<OctetString			>().Factory(), Cast.N, Tag.Context(0)	), 
		}; 
		// конструктор
		public SignerIdentifier() : base(info) {} 
	}
}
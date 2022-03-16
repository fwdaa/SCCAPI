using System;
using System.IO;
using System.Runtime.Serialization;

//	AuthorityKeyIdentifierOld ::= SEQUENCE {
//		keyIdentifier             [0] IMPLICIT OCTET STRING	OPTIONAL,
//		authorityCertIssuer       [1] IMPLICIT Name         OPTIONAL,
//		authorityCertSerialNumber [2] IMPLICIT INTEGER		OPTIONAL 
//	}

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	[Serializable]
	public class AuthorityKeyIdentifierOld : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<OctetString	>().Factory(), Cast.O, Tag.Context(0)), 
			new ObjectInfo(new ChoiceCreator<Name        	>().Factory(), Cast.O, Tag.Context(1)), 
			new ObjectInfo(new ObjectCreator<Integer		>().Factory(), Cast.O, Tag.Context(2)), 
		}; 
		// конструктор при сериализации
        protected AuthorityKeyIdentifierOld(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public AuthorityKeyIdentifierOld(IEncodable encodable) : base(encodable, info) 
		{
			// проверить наличие элементов
			if (AuthorityCertIssuer == null && AuthorityCertSerialNumber != null) throw new InvalidDataException();
			if (AuthorityCertIssuer != null && AuthorityCertSerialNumber == null) throw new InvalidDataException();
		}
		// конструктор при закодировании
		public AuthorityKeyIdentifierOld(OctetString keyIdentifier, 
			IEncodable authorityCertIssuer, Integer authorityCertSerialNumber) : 
			base(info, keyIdentifier, authorityCertIssuer, authorityCertSerialNumber)   
		{
			// проверить наличие элементов
			if (AuthorityCertIssuer == null && AuthorityCertSerialNumber != null) throw new ArgumentException();
			if (AuthorityCertIssuer != null && AuthorityCertSerialNumber == null) throw new ArgumentException();
		}
		public OctetString	KeyIdentifier				{ get { return (OctetString	)this[0]; }} 
		public IEncodable   AuthorityCertIssuer			{ get { return (IEncodable  )this[1]; }}
		public Integer		AuthorityCertSerialNumber	{ get { return (Integer		)this[2]; }}

		// выполнить преобразование типа
		public AuthorityKeyIdentifier Update() 
		{
			// переопределить используемый тип
			IEncodable encodable = Explicit.Encode(Tag.Context(4), AuthorityCertIssuer); 

			// указать издателя сертификата
			GeneralNames names = new GeneralNames(new IEncodable[] { encodable }); 
        
			// выполнить преобразование типа
			return new AuthorityKeyIdentifier(KeyIdentifier, names, AuthorityCertSerialNumber); 
		}
	}
}

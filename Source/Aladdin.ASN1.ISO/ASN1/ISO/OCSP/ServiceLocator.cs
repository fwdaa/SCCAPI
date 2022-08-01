using System;
using System.Runtime.Serialization;

// ServiceLocator ::= SEQUENCE {
//     issuer    Name,
//     locator   AuthorityInfoAccessSyntax 
// }

namespace Aladdin.ASN1.ISO.OCSP
{
	[Serializable]
	public class ServiceLocator : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ChoiceCreator<PKIX.Name							>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<PKIX.CE.AuthorityInfoAccessSyntax	>().Factory(), Cast.N) 
		}; 
		// конструктор при сериализации
        protected ServiceLocator(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public ServiceLocator(IEncodable encodable) : base(encodable, info) {} 

		// конструктор при закодировании
		public ServiceLocator(IEncodable issuer, PKIX.CE.AuthorityInfoAccessSyntax locator) : 
			base(info, issuer, locator) {} 

		public IEncodable							Issuer	{ get { return (IEncodable							)this[0]; } } 
		public PKIX.CE.AuthorityInfoAccessSyntax	Locator	{ get { return (PKIX.CE.AuthorityInfoAccessSyntax	)this[1]; } }
	}
}

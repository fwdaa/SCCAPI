using System; 

//	PolicyMapping ::= SEQUENCE {
//		issuerDomainPolicy      OBJECT IDENTIFIER,
//		subjectDomainPolicy     OBJECT IDENTIFIER 
//	}

namespace Aladdin.ASN1.ISO.PKIX.CE
{
	public class PolicyMapping : Sequence
	{
		// информация о структуре
		private static readonly ObjectInfo[] info = new ObjectInfo[] { 

			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
			new ObjectInfo(new ObjectCreator<ObjectIdentifier>().Factory(), Cast.N), 
		}; 
		// конструктор при раскодировании
		public PolicyMapping(IEncodable encodable) : base(encodable, info) {}

		// конструктор при закодировании
		public PolicyMapping(ObjectIdentifier issuerDomainPolicy, ObjectIdentifier subjectDomainPolicy) 
            : base(info, issuerDomainPolicy, subjectDomainPolicy) {}

		public ObjectIdentifier	IssuerDomainPolicy  { get { return (ObjectIdentifier)this[0]; } } 
		public ObjectIdentifier SubjectDomainPolicy { get { return (ObjectIdentifier)this[1]; } }
	}
}

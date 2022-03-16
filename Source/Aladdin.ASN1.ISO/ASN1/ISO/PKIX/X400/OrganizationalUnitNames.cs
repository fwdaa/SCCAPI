using System;
using System.IO;
using System.Runtime.Serialization;

// OrganizationalUnitNames ::= SEQUENCE SIZE (1..ub-organizational-units) OF OrganizationalUnitName
// ub-organizational-units INTEGER ::= 4

// OrganizationalUnitName ::= PrintableString (SIZE (1..ub-organizational-unit-name-length))
// ub-organizational-unit-name-length INTEGER ::= 32

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	[Serializable]
	public class OrganizationalUnitNames : Sequence<PrintableString>
	{
		// конструктор при сериализации
        protected OrganizationalUnitNames(SerializationInfo info, StreamingContext context) : base(info, context) {}

		// конструктор при раскодировании
		public OrganizationalUnitNames(IEncodable encodable) : base(encodable) 
		{
			// проверить корректность
			if (Length <= 0 || Length > 4) throw new InvalidDataException(); 

			// проверить корректность элементов
			foreach (PrintableString obj in this) PrintableString.Validate(obj, false, 1, 32); 
		} 
		// конструктор при закодировании
		public OrganizationalUnitNames(params PrintableString[] values) : base(values) 
		{
			// проверить корректность
			if (Length <= 0 || Length > 4) throw new ArgumentException(); 

			// проверить корректность элементов
			foreach (PrintableString obj in this) PrintableString.Validate(obj, true, 1, 32); 
		} 
	}
}

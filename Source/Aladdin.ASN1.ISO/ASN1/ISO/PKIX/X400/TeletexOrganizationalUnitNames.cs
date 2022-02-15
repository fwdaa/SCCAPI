using System;
using System.IO;

// TeletexOrganizationalUnitNames ::= SEQUENCE SIZE (1..ub-organizational-units) OF TeletexOrganizationalUnitName
// ub-organizational-units INTEGER ::= 4

// TeletexOrganizationalUnitName ::= TeletexString (SIZE (1..ub-organizational-unit-name-length))
// ub-organizational-unit-name-length INTEGER ::= 32

namespace Aladdin.ASN1.ISO.PKIX.X400
{
	public class TeletexOrganizationalUnitNames : Sequence<TeletexString>
	{
		// конструктор при раскодировании
		public TeletexOrganizationalUnitNames(IEncodable encodable) : base(encodable) 
		{
			// проверить корректность
			if (Length <= 0 || Length > 4) throw new InvalidDataException(); 

			// проверить корректность элементов
			foreach (TeletexString obj in this) TeletexString.Validate(obj, false, 1, 32); 
		} 
		// конструктор при закодировании
		public TeletexOrganizationalUnitNames(params TeletexString[] values) : base(values) 
		{
			// проверить корректность
			if (Length <= 0 || Length > 4) throw new ArgumentException(); 

			// проверить корректность элементов
			foreach (TeletexString obj in this) TeletexString.Validate(obj, true, 1, 32); 
		} 
	}
}

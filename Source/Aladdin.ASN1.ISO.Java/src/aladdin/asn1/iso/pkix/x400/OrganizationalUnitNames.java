package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*; 
import java.io.*; 

// OrganizationalUnitNames ::= SEQUENCE SIZE (1..ub-organizational-units) OF OrganizationalUnitName
// ub-organizational-units INTEGER ::= 4

// OrganizationalUnitName ::= PrintableString (SIZE (1..ub-organizational-unit-name-length))
// ub-organizational-unit-name-length INTEGER ::= 32

public final class OrganizationalUnitNames extends Sequence<PrintableString>
{
	// конструктор при раскодировании
	public OrganizationalUnitNames(IEncodable encodable) throws IOException
	{
		// вызвать базовую функцию
		super(PrintableString.class, encodable); 

		// проверить корретность
		if (size() <= 0 || size() > 4) throw new IOException();

		// проверить корректность элементов
		for (PrintableString obj : this) 
		{
			// проверить корректность элемента
			PrintableString.validate(obj, false, 1, 32);
		} 
	} 
	// конструктор при закодировании
	public OrganizationalUnitNames(PrintableString... values) 
	{
		// вызвать базовую функцию
		super(PrintableString.class, values); 
		
		// проверить корретность
		if (size() <= 0 || size() > 4) throw new IllegalArgumentException();

		// проверить корректность элементов
		for (PrintableString obj : this) 
		{
			// проверить корректность элемента
			try { PrintableString.validate(obj, true, 1, 32); }

            // пропустить невозможную ошибку
            catch (IOException e) { throw new RuntimeException(e); } 
		} 
	} 
}

package aladdin.asn1.iso.pkix.x400;
import aladdin.asn1.*;
import java.io.*; 

// TeletexOrganizationalUnitNames ::= SEQUENCE SIZE (1..ub-organizational-units) OF TeletexOrganizationalUnitName
// ub-organizational-units INTEGER ::= 4

// TeletexOrganizationalUnitName ::= TeletexString (SIZE (1..ub-organizational-unit-name-length))
// ub-organizational-unit-name-length INTEGER ::= 32

public final class TeletexOrganizationalUnitNames extends Sequence<TeletexString>
{
	// конструктор при раскодировании
	public TeletexOrganizationalUnitNames(IEncodable encodable) throws IOException 
	{
		super(TeletexString.class, encodable); 
		
		// проверить корректность
		if (size() <= 0 || size() > 4) throw new IOException(); 

		// проверить корректность элементов
		for (TeletexString obj : this) 
		{
			// проверить корректность элемента
			TeletexString.validate(obj, false, 1, 32);
		} 
	} 
	// конструктор при закодировании
	public TeletexOrganizationalUnitNames(TeletexString... values) 
	{
		super(TeletexString.class, values); 
		
		// проверить корректность
		if (size() <= 0 || size() > 4) throw new IllegalArgumentException(); 

		// проверить корректность элементов
		for (TeletexString obj : this) 
		{
			// проверить корректность элемента
			try { TeletexString.validate(obj, true, 1, 32); }

            // пропустить невозможную ошибку
            catch (IOException e) { throw new RuntimeException(e); } 
		} 
	} 
}

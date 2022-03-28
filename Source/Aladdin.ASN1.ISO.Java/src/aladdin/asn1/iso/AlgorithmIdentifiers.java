package aladdin.asn1.iso;
import aladdin.asn1.*; 
import java.io.*;

// AlgorithmIdentifiers ::= SET OF AlgorithmIdentifier

public final class AlgorithmIdentifiers extends Set<AlgorithmIdentifier>
{
    private static final long serialVersionUID = 1181741206056796749L;
    
	// конструктор при раскодировании
	public AlgorithmIdentifiers(IEncodable encodable) throws IOException 
	{
		super(AlgorithmIdentifier.class, encodable); 
	} 
	// конструктор при закодировании
	public AlgorithmIdentifiers(AlgorithmIdentifier... values) 
	{
		super(AlgorithmIdentifier.class, values); 
	} 
	// найти требуемый атрибут
	public AlgorithmIdentifier get(String oid)
	{
		// для всех атрибутов
		for (AlgorithmIdentifier algorithm : this)
		{
			// проверить совпадение идентификатора
			if (algorithm.algorithm().value().equals(oid)) return algorithm; 
		}
		return null; 
	}
}

package aladdin.asn1.ansi.x962;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.io.*;

// ECCAlgorithms ::= SEQUENCE OF ECCAlgorithm

public final class ECCAlgorithms extends Sequence<AlgorithmIdentifier>
{
	// конструктор при раскодировании
	public ECCAlgorithms(IEncodable encodable) throws IOException 
	{
		super(AlgorithmIdentifier.class, encodable); 
	} 
	// конструктор при закодировании
	public ECCAlgorithms(AlgorithmIdentifier... values) 
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

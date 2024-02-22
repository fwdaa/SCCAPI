package aladdin.asn1;
import java.io.*; 

final class Utils
{
    /////////////////////////////////////////////////////////////////////////////
    // Закодировать строку
    /////////////////////////////////////////////////////////////////////////////
	public static byte[] encodeString(String value, String encoding)
	{
		// закодировать строку
		try { return value.getBytes(encoding); }
		
		// обработать возможную ошибку
		catch (UnsupportedEncodingException e) { throw new RuntimeException(e); }
	}
}
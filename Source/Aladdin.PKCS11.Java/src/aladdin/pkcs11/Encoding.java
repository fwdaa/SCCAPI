package aladdin.pkcs11;
import java.io.*; 

class Encoding 
{
	/////////////////////////////////////////////////////////////////////////////
	// Кодирование строк с дополнением
	/////////////////////////////////////////////////////////////////////////////
	public static String decodeString(byte[] encoded) throws IOException
	{
		// определить размер строки
		int ulSize = encoded.length; 
        
        // пропустить незначимые байты
        while (ulSize >= 1 && (encoded[ulSize - 1] == ' ' || encoded[ulSize - 1] == 0)) ulSize--; 

		// раскодировать строку
		return new String(encoded, 0, ulSize, "UTF-8"); 
	}
	public static String decodeString(char[] encoded) throws IOException
	{
		// определить размер строки
		int ulSize = encoded.length; 
        
        // пропустить незначимые символы
        while (ulSize >= 1 && (encoded[ulSize - 1] == ' ' || encoded[ulSize - 1] == 0)) ulSize--; 

		// раскодировать строку
		return new String(encoded, 0, ulSize); 
	}
	/////////////////////////////////////////////////////////////////////////////
	// Шестнадцатеричное представление массива
	/////////////////////////////////////////////////////////////////////////////
    public static byte[] fromHex(String value) throws IOException
    {
	    // проверить размер строки
	    if ((value.length() % 2) != 0) throw new IOException(); 

	    // проверить наличие только цифр
	    for (int i = 0; i < value.length(); i++)
	    {
            // извлечь символ строки
            char ch = value.charAt(i); 
            
		    // проверить наличие только цифр
		    if (Character.isDigit(ch)) continue; 

		    // проверить наличие шестнадцатеричных символов
		    if ('A' <= ch && ch <= 'F') continue;
		    if ('a' <= ch && ch <= 'f') continue;

            // при ошибке выбросить исключение
		    throw new IOException();
	    }
        // выделить буфер требуемого размера
	    byte[] buffer = new byte[value.length() / 2];  

	    // для каждого байта
	    for (int i = 0; i < value.length() / 2; i++)
	    {	
            // извлечь подстроку
            String substr = value.substring(2 * i, 2 * i + 2); 
            
            // раскодировать байт
            buffer[i] = (byte)(Short.parseShort(substr, 16) & 0xFF); 
	    }
	    return buffer; 
    }
}

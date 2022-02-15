using System;
using System.Text;
using System.Globalization;
using System.IO;

namespace Aladdin.PKCS11
{
    internal static class Encoding
    {
	    /////////////////////////////////////////////////////////////////////////////
	    // Кодирование строк с завершающим нулем и дополнением
	    /////////////////////////////////////////////////////////////////////////////
	    public static byte[] EncodeString(String value)
	    {
		    // закодировать строку
		    byte[] buffer = System.Text.Encoding.UTF8.GetBytes(value); 

		    // выделить память для строки
		    Array.Resize(ref buffer, buffer.Length + 1); 

		    // скопировать строку
		    buffer[buffer.Length - 1] = 0; return buffer; 
	    }
	    public static byte[] EncodeString(String value, int ulSize)
	    {
		    // закодировать строку
		    byte[] buffer = System.Text.Encoding.UTF8.GetBytes(value); 

		    // проверить размер метки
		    if (buffer.Length > ulSize) Exception.Check(API.CKR_ARGUMENTS_BAD); 

		    // заполнить буфер пробелами
            byte[] encoded = new byte[ulSize]; for (int i = 0; i < ulSize; i++) encoded[i] = 0x20; 

		    // скопировать закодированную строку
		    Array.Copy(buffer, 0, encoded, 0, buffer.Length); return encoded;
	    }
	    public static String DecodeString(byte[] encoded, int ulSize)
	    {
		    // определить размер строки
		    while (ulSize >= 1 && (encoded[ulSize - 1] == 0x20 || encoded[ulSize - 1] == 0x0)) ulSize--; 

		    // выделить память для строки
		    byte[] buffer = new byte[ulSize]; 

		    // скопировать строку
		    Array.Copy(encoded, 0, buffer, 0, ulSize); 

		    // раскодировать строку
		    return System.Text.Encoding.UTF8.GetString(buffer); 
	    }
	    /////////////////////////////////////////////////////////////////////////////
	    // Шестнадцатеричное представление массива
	    /////////////////////////////////////////////////////////////////////////////
	    public static byte[] FromHex(String value)
	    {
	        // проверить размер строки
	        if ((value.Length % 2) != 0) throw new InvalidDataException(); 

	        // проверить наличие только цифр
	        for (int i = 0; i < value.Length; i++)
	        {
		        // проверить наличие только цифр
		        if (Char.IsDigit(value[i])) continue; 

		        // проверить наличие шестнадцатеричных символов
		        if ('A' <= value[i] && value[i] <= 'F') continue;
		        if ('a' <= value[i] && value[i] <= 'f') continue;

                // при ошибке выбросить исключение
		        throw new InvalidDataException(); 
	        }
            // указать способ кодирования
            NumberStyles style = NumberStyles.AllowHexSpecifier; 

	        // выделить буфер требуемого размера
	        byte[] buffer = new byte[value.Length / 2];  

	        // для каждого байта
	        for (int i = 0; i < value.Length / 2; i++)
	        {	
                // раскодировать байт
                buffer[i] = Byte.Parse(value.Substring(2 * i, 2), style); 
	        }
	        return buffer; 
	    }
    }
}

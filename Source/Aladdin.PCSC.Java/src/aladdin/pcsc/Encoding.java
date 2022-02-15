package aladdin.pcsc;
import java.util.*;

abstract class Encoding 
{
    ///////////////////////////////////////////////////////////////////////
    // Кодирование мультистрок
    ///////////////////////////////////////////////////////////////////////
    public static String encodeMultiString(String[] strings)
    {
        // проверить указание строк
        if (strings == null) return null; 

        // выделить вспомогательный буфер
        StringBuilder multiString = new StringBuilder(); 

        // для всех строк
        for (int i = 0; i < strings.length; i++)
        {
            // проверить наличие строки
            if (strings[i].length() == 0) continue; 

            // добавить строку в буфер
            multiString.append(strings[i]); multiString.append('\0'); 
        }
        // добавить завершающий символ
        if (multiString.length() == 0) multiString.append('\0');

        // вернуть мультистроку
        return multiString.toString(); 
    }
    public static String[] decodeMultiString(String multiString)
    {
        // проверить указание строки
        if (multiString == null) return null; int start = 0; 

        // создать список строк
        List<String> strings = new ArrayList<String>(); 
            
        // найти завершение первой внутренней строки
        int index = multiString.indexOf('\0', start); 

        // для всех внутренних строк
        for (; index >= 0; start = index + 1, index = multiString.indexOf('\0', start))
        {
            // проверить наличие строки
            if (index == start) continue; 

            // извлечь внутреннюю строку
            strings.add(multiString.substring(start, index)); 
        }
        // при наличии незавершенной строки
        if (start < multiString.length())
        {
            // извлечь незавершенную строку
            strings.add(multiString.substring(start)); 
        }
        // вернуть список строк
        return strings.toArray(new String[strings.size()]); 
    }
}

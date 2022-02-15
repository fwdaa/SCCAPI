package aladdin;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Стек вызова
///////////////////////////////////////////////////////////////////////////////
public class StackTrace 
{
    // получить стек исключения
    public static String fromException(Throwable throwable)
    {
        // создать динамический буфер
        StringWriter writer = new StringWriter(); 

        // указать поток вывода
        try (PrintWriter printWriter = new PrintWriter(writer))
        {
            // получить стековый фрейм
            throwable.printStackTrace(printWriter);
        }
        // получить описание исключения и стековый фрейм
        String message = throwable.toString(); String stackTrace = writer.toString(); 

        // найти позицию разделителя
        int index = stackTrace.indexOf(message); if (index >= 0)
        {
            // удалить текст исключения из описания
            stackTrace = stackTrace.substring(index + message.length()); 
        }
        // получить разделитель строк
        String nl = System.getProperty("line.separator"); 
        
        // выполнить замены 
        stackTrace = stackTrace.replace(nl + "\tat ", nl); if (stackTrace.startsWith(nl)) 
        {
            // удалить первый перевод строки
            stackTrace = stackTrace.substring(nl.length());
        }
        return stackTrace; 
    }
    // сформировать сообщение об ошибке
    public static String getExceptionTrace(String message, String stackTrace)
    {
        // получить разделитель строк
        String nl = System.getProperty("line.separator"); 
        
        // выполнить замены
        stackTrace = stackTrace.replace(nl, nl + "\tat "); 

        // при необходимости
        if (stackTrace.endsWith(nl + "\tat ")) 
        {
            // удалить последнюю табуляцию
            stackTrace = stackTrace.substring(0, stackTrace.length() - 4); 
        }
        // добавить описание исключения
        return String.format("%1$s%2$s%3$s", message, nl, stackTrace); 
    }
    // получить стековый фрейм указанной вложенности
    public static String getFrame(int depth)
    {
        // указать имя класса
        String className = "aladdin.StackTrace"; 
        
        // получить информацию о вызове
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace(); 
        
        // для всех стековых фреймов
        int base = 0; for(; base < stackTrace.length; base++)
        {
            // проверить совпадение имени класса
            if (stackTrace[base].getClassName().equals(className)) break; 
        }
        // требуемый стековый фрейм не найден
        if (base >= stackTrace.length - 1 - depth) return new String(); 

        // вернуть требуемый стековый фрейм
        return stackTrace[base + 1 + depth].toString(); 
    }
}

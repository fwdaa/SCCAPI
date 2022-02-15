package aladdin.net;
import aladdin.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Исключение
///////////////////////////////////////////////////////////////////////////
public class SerialException extends IOException
{
    // номер версии при сериализации
    private static final long serialVersionUID = -1896353424275635162L;
    
    // закодировать исключение
    public static String toString(Throwable exception, boolean escape)
    {
        // получить описание исключения
        String message = exception.toString(); 
        
        // получить стековый фрейм
        String stackTrace = StackTrace.fromException(exception); 

        // объединить описание ошибки и стековый фрейм
        if (!escape) return String.format("%1$s\000%2$s", message, stackTrace); 

        // получить разделитель строк
        String nl = System.getProperty("line.separator"); 
        
        // заменить символы перевода строки
        message    = message   .replace(nl, "\n"); 
        stackTrace = stackTrace.replace(nl, "\n"); 

        // выполнить экранирование
        message    = message   .replace("\\", "\\\\").replace("\n", "\\n"); 
        stackTrace = stackTrace.replace("\\", "\\\\").replace("\n", "\\n"); 

        // объединить описание и стек исключения
        return String.format("%1$s\n%2$s", message, stackTrace); 
    }
    // раскодировать исключение
    public static Exception fromString(String description)
    {
        // найти разделитель строк
        int index = description.indexOf('\000'); if (index >= 0)
        {
            // извлечь описание ошибки
            String message = description.substring(0, index); 

            // извлечь стековый фрейм
            String stackTrace = description.substring(index + 1); 

            // вернуть исключение
            return new SerialException(message, stackTrace);
        }
        // найти разделитель строк
        index = description.indexOf('\n'); if (index >= 0)
        {
            // извлечь описание ошибки
            String message = description.substring(0, index); 

            // извлечь стековый фрейм
            String stackTrace = description.substring(index + 1); 

            // отменить экранирование
            message    = message   .replace("\\n", "\n").replace("\\\\", "\\");
            stackTrace = stackTrace.replace("\\n", "\n").replace("\\\\", "\\");

            // получить разделитель строк
            String nl = System.getProperty("line.separator"); 
            
            // изменить символы перевода строки
            message    = message   .replace("\n", nl); 
            stackTrace = stackTrace.replace("\n", nl); 

            // вернуть исключение
            return new SerialException(message, stackTrace);
        }
        // вернуть исключение
        return new SerialException(description, new String());
    }
    // стековый фрейм исключения
    private final String stackTrace;
        
    // конструктор
    private SerialException(String message, String stackTrace) { super(message); 
            
        // добавить описание исключения
        this.stackTrace = StackTrace.getExceptionTrace(message, stackTrace); 
    }
    // стековый фрейм исключения
    @Override
    public void printStackTrace() { printStackTrace(System.err); }
    @Override
    public void printStackTrace(PrintStream s) { s.print(stackTrace); }
    @Override
    public void printStackTrace(PrintWriter s) { s.print(stackTrace); }
}

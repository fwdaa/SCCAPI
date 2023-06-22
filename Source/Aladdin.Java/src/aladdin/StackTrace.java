package aladdin;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Стек вызова
///////////////////////////////////////////////////////////////////////////////
public class StackTrace 
{
    // получить стековый фрейм указанной вложенности
    public static String[] fromCurrent(int skip)
    {
        // получить информацию о вызове
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace(); 
        
        // для всех стековых фреймов
        int base = 0; for(; base < stackTrace.length; base++)
        {
            // проверить совпадение имени класса
            if (stackTrace[base].getClassName().equals("aladdin.StackTrace")) break; 
        }
        // требуемый стековый фрейм не найден
        if (base >= stackTrace.length - 1 - skip) return new String[0]; 
        
        // создать список строк
        List<String> stackFrames = new ArrayList<String>(); 
        
        // для всех кадров стека 
        for (int i = base + 1 + skip; i < stackTrace.length; i++)
        {
            // добавить строку в список 
            stackFrames.add(stackTrace[i].toString());
        }
        // вернуть список строк
        return stackFrames.toArray(new String[stackFrames.size()]); 
    }
    // получить стек исключения
    public static String[] fromException(Throwable throwable)
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
        // удалить незначащие пробелы
        stackTrace = stackTrace.trim(); if (stackTrace.length() == 0) return new String[0]; 
        
        // создать список строк
        List<String> stackFrames = new ArrayList<String>(); 
        
        // получить разделитель строк
        String nl = System.getProperty("line.separator"); int start = 0; 
            
        // получить позицию разделителя 
        for (index = stackTrace.indexOf(nl, start); index >= 0; index = stackTrace.indexOf(nl, start))
        {
            // извлечь строку 
            String frame = stackTrace.substring(start, index); 
            
            // удалить табуляцию
            if (frame.startsWith("\tat ")) frame = frame.substring(4); 
            
            // добавить строку в список 
            stackFrames.add(frame); start = index + nl.length(); 
        }{
            // извлечь строку 
            String frame = stackTrace.substring(start); 
        
            // удалить табуляцию
            if (frame.startsWith("\tat ")) frame = frame.substring(4); 

            // добавить строку в список 
            stackFrames.add(frame); 
        }
        // вернуть список строк
        return stackFrames.toArray(new String[stackFrames.size()]); 
    }
    // сформировать сообщение об ошибке
    public static String toString(String[] stackTrace)
    {
        // получить разделитель строк
        String nl = System.getProperty("line.separator"); 
        
        // создать строковый буфер 
        StringBuilder buffer = new StringBuilder(); 
        
        // для всех кадров стека 
        for (int i = 0; i < stackTrace.length; i++)
        {
            // добавить разделитель
            if (buffer.length() != 0) buffer.append(nl);

            // добавить описание фрейма 
            buffer.append(stackTrace[i]); 
        }
        // вернуть строковый буфер 
        return buffer.toString(); 
    }
    // получить строковое представление исключения 
    public static String toExceptionString(String[] stackTrace, String message)
    {
        // получить разделитель строк
        String nl = System.getProperty("line.separator"); 
        
        // создать строковый буфер 
        StringBuilder buffer = new StringBuilder(message); 
        
        // для всех кадров стека 
        for (int i = 0; i < stackTrace.length; i++)
        {
            // добавить разделитель
            buffer.append(nl); buffer.append("\tat "); 

            // добавить описание фрейма 
            buffer.append(stackTrace[i]); 
        }
        // вернуть строковый буфер 
        return buffer.toString(); 
    }
}

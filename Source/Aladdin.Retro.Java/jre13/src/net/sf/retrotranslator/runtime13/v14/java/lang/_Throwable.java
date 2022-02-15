package net.sf.retrotranslator.runtime13.v14.java.lang;
import net.sf.retrotranslator.runtime13.impl.*;
import java.io.*;
import java.lang.reflect.*;
import java.security.*;
import java.awt.print.*;
import java.rmi.*;
import java.rmi.activation.*;
import java.rmi.server.*;
import java.util.*;
import javax.naming.*;

public class _Throwable
{
    ///////////////////////////////////////////////////////////////////////////
    // Вспомогательные таблицы
    ///////////////////////////////////////////////////////////////////////////
    
    // признак отсутствия вложенного исключения
    private static final Throwable NULL = new Throwable();
    
    // таблица соответствия исключений и вложенных исключений
    private static final WeakIdentityTable causeTable = new WeakIdentityTable();
    
    // сохранить соответствие исключения и вложенного исключения
    private static void saveCause(Throwable throwable, Throwable cause)
    {
        synchronized (throwable)
        {
            // проверить отсутствие исключения
            if (causeTable.lookup(throwable) != null) throw new IllegalStateException();
            
            // проверить корректность данных
            if (throwable == cause) throw new IllegalArgumentException();
        
            // добавить соответствие исключения и вложенного исключения
            causeTable.putIfAbsent(throwable, cause == null ? NULL : cause);
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Конструкторы 
    ///////////////////////////////////////////////////////////////////////////
    public static ThrowableBuilder createInstanceBuilder(String message, Throwable cause)
    {
        // создать вспомогательный объект
        return new ThrowableBuilder(message, cause);
    }
    public static ThrowableBuilder createInstanceBuilder(Throwable cause)
    {
        // создать вспомогательный объект
        return new ThrowableBuilder(cause == null ? null : cause.toString(), cause);
    }
    public static class ThrowableBuilder
    {
        // параметры конструктора исключения
        private final String message; private final Throwable cause;

        // конструктор
        protected ThrowableBuilder(String message, Throwable cause)
        {
            // сохранить переданные параметры
            this.message = message; this.cause = cause;
        }
        // вызвать существующий конструктор с параметром-строкой
        public String argument1() { return this.message; }
    
        // выполнить дополнительную инициализацию
        public void initialize(Throwable throwable)
        {
            // установить вложенное исключение
            _Throwable.initCause(throwable, this.cause);
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Методы
    ///////////////////////////////////////////////////////////////////////////
    
    // установить вложенное исключение
    public static Throwable initCause(Throwable throwable, Throwable cause)
    {
        // проверить корректность вызова
        if (throwable instanceof ExceptionInInitializerError ) throw new IllegalStateException();
        if (throwable instanceof ClassNotFoundException      ) throw new IllegalStateException();
        if (throwable instanceof InvocationTargetException   ) throw new IllegalStateException();
        if (throwable instanceof UndeclaredThrowableException) throw new IllegalStateException();
        if (throwable instanceof PrivilegedActionException   ) throw new IllegalStateException();
        if (throwable instanceof RemoteException             ) throw new IllegalStateException();
        if (throwable instanceof WriteAbortedException       ) throw new IllegalStateException();
        if (throwable instanceof ActivationException         ) throw new IllegalStateException();
        if (throwable instanceof ServerCloneException        ) throw new IllegalStateException();
        if (throwable instanceof PrinterIOException          ) throw new IllegalStateException();
        
        // при наличии эквивалентной функциональности
        if ((throwable instanceof NamingException))
        {
            // выполнить эквивалентную функциональность
            ((NamingException)throwable).setRootCause(cause);
            
            // не использовать вспомогательную таблицу
            saveCause(throwable, null);
        }
        // сохранить соответствие исключений
        else saveCause(throwable, cause); return throwable; 
    }
    // получить вложенное исключение
    public static Throwable getCause(Throwable throwable)
    {
        // для специального типа исключений
        if (throwable instanceof ExceptionInInitializerError) 
        {
            // получить вложенное исключение
            return ((ExceptionInInitializerError)throwable).getException();
        }
        // для специального типа исключений
        if (throwable instanceof ClassNotFoundException) 
        {
            // получить вложенное исключение
            return ((ClassNotFoundException)throwable).getException();
        }
        // для специального типа исключений
        if (throwable instanceof InvocationTargetException) 
        {
            // получить вложенное исключение
            return ((InvocationTargetException)throwable).getTargetException();
        }
        // для специального типа исключений
        if (throwable instanceof UndeclaredThrowableException) 
        {
            // получить вложенное исключение
            return ((UndeclaredThrowableException)throwable).getUndeclaredThrowable();
        }
        // для специального типа исключений
        if (throwable instanceof PrivilegedActionException) 
        {
            // получить вложенное исключение
            return ((PrivilegedActionException)throwable).getException();
        }
        // для специального типа исключений
        if (throwable instanceof RemoteException) 
        {
            // получить вложенное исключение
            return ((RemoteException)throwable).detail;
        }
        // для специального типа исключений
        if (throwable instanceof WriteAbortedException) 
        {
            // получить вложенное исключение
            return ((WriteAbortedException)throwable).detail;
        }
        // для специального типа исключений
        if (throwable instanceof ActivationException) 
        {
            // получить вложенное исключение
            return ((ActivationException)throwable).detail;
        }
        // для специального типа исключений
        if (throwable instanceof ServerCloneException) 
        {
            // получить вложенное исключение
            return ((ServerCloneException)throwable).detail;
        }
        // для специального типа исключений
        if (throwable instanceof PrinterIOException) 
        {
            // получить вложенное исключение
            return ((PrinterIOException)throwable).getIOException();
        }
        // для специального типа исключений
        if (throwable instanceof NamingException) 
        {
            // получить вложенное исключение
            return ((NamingException)throwable).getRootCause();
        }
        // найти вложенное исключение в таблице
        Throwable result = (Throwable)causeTable.lookup(throwable);
        
        // вернуть вложенное исключение
        return result == NULL ? null : result;
    }
    // добавить подавленное исключение
    public static void addSuppressed(Throwable self, Throwable suppressed) {}
  
    // получить стек исключения
    public static StackTraceElement_[] getStackTrace(Throwable throwable)
    {
        // создать динамический буфер
        StringWriter writer = new StringWriter(); List result = new ArrayList();
        
        // сохранить строковое описание стека исключения
        throwable.printStackTrace(new PrintWriter(writer));
        
        // создать построчный считыватель 
        BufferedReader reader = new BufferedReader(
            new StringReader(writer.toString())
        );
        try {
            // для всех строк из описание стека исключения
            for (String s = reader.readLine(); s != null; s = reader.readLine())
            {
                // при наличии описания места исключения
                if (s.startsWith("\tat "))
                {
                    // извлечь строковое описание места исключения
                    String substr = s.substring("\tat ".length()); 

                    // сохранить описание места исключения
                    result.add(StackTraceElement_.valueOf(substr));
                }
                // проверить достижение окончания
                else if (!result.isEmpty()) break; 
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new Error(e.getMessage()); }
        
        // выделить буфер стека исключения
        StackTraceElement_[] buffer = new StackTraceElement_[result.size()]; 
        
        // заполнить буфер стека исключения
        return (StackTraceElement_[])result.toArray(buffer);
  }
}

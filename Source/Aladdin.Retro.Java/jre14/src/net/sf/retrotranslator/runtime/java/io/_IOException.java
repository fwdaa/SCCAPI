package net.sf.retrotranslator.runtime.java.io;
import java.io.*; 

public class _IOException 
{
    ///////////////////////////////////////////////////////////////////////////
    // Конструкторы 
    ///////////////////////////////////////////////////////////////////////////
    public static Builder createInstanceBuilder(String message, Throwable cause)
    {
        // создать вспомогательный объект
        return new Builder(message, cause);
    }
    public static Builder createInstanceBuilder(Throwable cause)
    {
        // создать вспомогательный объект
        return new Builder(cause == null ? null : cause.toString(), cause);
    }
    public static class Builder
    {
        // параметры конструктора исключения
        private final String message; private final Throwable cause;

        // конструктор
        protected Builder(String message, Throwable cause)
        {
            // сохранить переданные параметры
            this.message = message; this.cause = cause;
        }
        // вызвать существующий конструктор с параметром-строкой
        public String argument1() { return this.message; }
    
        // выполнить дополнительную инициализацию
        public void initialize(IOException exception)
        {
            // установить вложенное исключение
            exception.initCause(cause); 
        }
    }
}

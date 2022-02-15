package aladdin.capi;
import java.io.*; 

/////////////////////////////////////////////////////////////////////////////
// Исключение аутентификации
//////////////////////////////////////////////////////////////////////////////
public class AuthenticationException extends IOException
{
    // номер версии для сериализации
    private static final long serialVersionUID = 2577402753526571019L;

    // конструктор
    public AuthenticationException(String message, Exception exception) { super(message, exception); } 
    // конструктор
    public AuthenticationException(String message) { super(message); } 
    // конструктор
    public AuthenticationException(Exception exception) { super(exception); } 
    // конструктор
    public AuthenticationException() { super(); } 
}


package aladdin.pcsc;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Исключение PC/SC
///////////////////////////////////////////////////////////////////////////////
public class Exception extends IOException
{
    // конструктор
    public Exception(int errorCode) { code = errorCode; } 

    // код ошибки
    public int getErrorCode() { return code; } private final int code;

    // уникальный идентификатор
    private static final long serialVersionUID = 6853106839840797635L;
}

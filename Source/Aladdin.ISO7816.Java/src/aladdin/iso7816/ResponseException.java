package aladdin.iso7816;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Ошибка выполнения APDU-команды
///////////////////////////////////////////////////////////////////////////
public class ResponseException extends IOException
{
    // номер версии для сериализации
    private static final long serialVersionUID = 6218341714864296781L;

    // проверить отсутствие ошибок
    public static void check(Response response) throws ResponseException
    {
        // проверить отсутствие ошибок
        if (!Response.error(response)) return; 
                
        // при ошибке выбросить исключение
        throw new ResponseException(response.SW);
    }
    // конструктор
    public ResponseException(short sw) { SW = sw; } public final short SW;
}

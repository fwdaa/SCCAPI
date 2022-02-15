using System; 
using System.IO; 

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////
    // Ошибка выполнения APDU-команды
    ///////////////////////////////////////////////////////////////////////////
    public partial class ResponseException : IOException
    {
        // проверить отсутствие ошибок
        public static void Check(Response response)
        {
            // проверить отсутствие ошибок
            if (!Response.Error(response)) return; 
                
            // при ошибке выбросить исключение
            throw new ResponseException(response.SW);
        }
    }
}

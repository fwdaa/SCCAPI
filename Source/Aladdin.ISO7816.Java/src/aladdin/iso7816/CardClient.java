package aladdin.iso7816;
import java.io.*; 
import java.util.Arrays;

///////////////////////////////////////////////////////////////////////////////
// Клиент взаимодействия со смарт-картой
///////////////////////////////////////////////////////////////////////////////
public abstract class CardClient 
{
    // обработать запрос от смарт-карты
    public Response reply(CardSession session, Command command, short sw) throws IOException
    {
        // указать класс команды
        byte cla = (command != null) ? command.CLA : (byte)0x00; 
        
        // создать команду GET DATA
        byte[] encoded = new byte[] { cla, INS.GET_DATA, 0x00, 0x00, (byte)(sw & 0xFF) }; 
        
        // выполнить команду
        Response response = new Response(session.sendCommand(encoded));
            
        // проверить корректность выполнения
        if (Response.error(response)) return response; 
            
        // сохранить полученные данные
        byte[] request = response.data; 
            
        // при наличии дополнительных данных
        while (0x6202 <= response.SW && response.SW <= 0x6280)
        {
            // указать требуемый размер данных
            encoded[4] = (byte)(response.SW & 0xFF); 
            
            // выполнить команду
            response = new Response(session.sendCommand(encoded));
            
            // проверить корректность выполнения
            if (Response.error(response)) return response; 
                
            // изменить размер буфера
            request = Arrays.copyOf(request, request.length + response.data.length); 
                
            // скопировать дополнительные данные
            System.arraycopy(response.data, 0, request, 
                request.length - response.data.length, response.data.length
            );
        }
        // ответить на запрос
        byte[] reply = reply(command, sw, request); 
            
        // выполнить команду
        return session.sendCommand(cla, INS.PUT_DATA, (byte)0x00, (byte)0x00, reply, 0);
    }
    // ответить на запрос карты
    public abstract byte[] reply(Command command, short sw, byte[] request) throws IOException; 
}

using System;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Клиент взаимодействия со смарт-картой
    ///////////////////////////////////////////////////////////////////////////////
    public abstract class CardClient 
    {
        // обработать запрос от смарт-карты
        public Response reply(CardSession session, Command command, ushort sw) 
        {
            // указать класс команды
            byte cla = (command != null) ? command.CLA : (byte)0x00; 

            // создать команду GET DATA
            byte[] encoded = new byte[] { cla, INS.GetData, 0x00, 0x00, (byte)(sw & 0xFF) }; 

            // выполнить команду
            Response response = new Response(session.SendCommand(encoded));
            
            // проверить корректность выполнения
            if (Response.Error(response)) return response; 
            
            // сохранить полученные данные
            byte[] request = response.Data; 
            
            // при наличии дополнительных данных
            while (0x6202 <= response.SW && response.SW <= 0x6280)
            {
                // указать требуемый размер данных
                encoded[4] = (byte)(response.SW & 0xFF); 

                // выполнить команду
                response = new Response(session.SendCommand(encoded));
            
                // проверить корректность выполнения
                if (Response.Error(response)) return response; 
                
                // изменить размер буфера
                Array.Resize(ref request, request.Length + response.Data.Length); 
                
                // скопировать дополнительные данные
                Array.Copy(response.Data, 0, request, 
                    request.Length - response.Data.Length, response.Data.Length
                );
            }
            // ответить на запрос
            byte[] reply = Reply(command, sw, request); 
            
            // выполнить команду
            return session.SendCommand(cla, INS.PutData, 0x00, 0x00, reply, 0);
        }
        // ответить на запрос карты
        public abstract byte[] Reply(Command command, ushort sw, byte[] request); 
    }
}

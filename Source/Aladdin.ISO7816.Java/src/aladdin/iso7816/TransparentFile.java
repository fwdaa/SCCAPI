package aladdin.iso7816;
import aladdin.iso7816.ber.*; 
import aladdin.util.*; 
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Элементарный бинарный файл 
///////////////////////////////////////////////////////////////////////////////
public class TransparentFile extends ElementaryFile
{
    // конструктор
    protected TransparentFile(DedicatedFile parent, short id) throws IOException
    { 
        // сохранить переданные параметры
        super(parent, id); 
    }
    // конструктор
    protected TransparentFile(DedicatedFile parent, byte shortID) throws IOException
    { 
        // сохранить переданные параметры
        super(parent, shortID);
    }
    // конструктор
    protected TransparentFile(DedicatedFile parent, 
        Short id, Byte shortID, FileControlInformation info) throws IOException
    { 
        // сохранить переданные параметры
        super(parent, id, shortID, info); 
    }
    // структура файла
    @Override public FileStructure fileStructure() { return FileStructure.TRANSPARENT; }
    
    ///////////////////////////////////////////////////////////////////////////
    // Прочитать содержимое файла
    ///////////////////////////////////////////////////////////////////////////
    @Override public Response readContent(LogicalChannel channel, 
        int secureType, SecureClient secureClient) throws IOException
    {
        // прочитать содержимое файла
        return readContent(channel, secureType, secureClient, 0, -1); 
    }
    public Response readContent(LogicalChannel channel, 
        int secureType, SecureClient secureClient, int offset, int length) throws IOException
    {
        // проверить необходимость действий
        if (length == 0) return new Response(new byte[0], (short)0x9000); 
        
        // прочитать содержимое файла
        Response response = readContent0(channel, 
            secureType, secureClient, offset, length
        ); 
        // проверить отсутствие ошибок
        if (!Response.error(response)) return response;
            
        // прочитать содержимое файла
        Response responseBERTLV = readContentBERTLV(
            channel, secureType, secureClient, offset, length
        ); 
        // проверить отсутствие ошибок
        return (!Response.error(responseBERTLV)) ? responseBERTLV : response;
    }
    // прочитать бинарный файл
    private Response readContent0(LogicalChannel channel, 
        int secureType, SecureClient secureClient, int offset, int length) throws IOException
    {
        // получить возможности карты
        CardCapabilities cardCapabilities = channel.environment().cardCapabilities(); 
        
        // определить максимальный размер данных
        int maxPart = (cardCapabilities.supportExtended()) ? 65536 : 256; 
        
        // указать параметры команды
        byte p1 = (byte)((offset >>> 8) & 0xFF); byte p2 = (byte)(offset & 0xFF); byte[] data = new byte[0]; 

        // выполнить команду
        Response response = channel.sendCommand(secureType, 
            secureClient, INS.READ_BINARY, p1, p2, new byte[0], -1
        ); 
        // при отсутствии ошибок
        if (!Response.error(response))
        {
            // до полного считывания данных
            while (!Response.error(response))
            {
                // для последних данных
                if (response.data.length < maxPart && response.SW == 0x6282) 
                {
                    // изменить код завершения
                    response = new Response(response.data, (short)0x9000);
                } 
                // извлечь прочитанные данные
                byte[] responseData = response.data; 

                // изменить размер буфера
                data = Arrays.copyOf(data, data.length + responseData.length); 

                // скопировать прочитанные данные
                System.arraycopy(responseData, 0, data, 
                    data.length - responseData.length, responseData.length
                ); 
                // при достаточности прочитанных данных
                if (length >= 0 && data.length >= length) 
                {
                    // вернуть прочитанные данные
                    data = Arrays.copyOf(data, length); break;
                }
                // обработать последние данные в файле
                if (response.data.length < maxPart) break; offset += maxPart; 

                // изменить смещение
                p1 = (byte)(offset >>> 8); p2 = (byte)(offset & 0xFF);

                // выполнить команду
                response = channel.sendCommand(secureType, 
                    secureClient, INS.READ_BINARY, p1, p2, new byte[0], -1
                ); 
            }
            // проверить отсутствие ошибок
            if (Response.error(response)) return response;

            // вернуть результат
            return new Response(data, response.SW); 
        }
        // при наличии сокращенного идентификатора
        if (offset <= 255 && shortID() != null)
        {
            // указать параметры команды
            p1 = (byte)(0x80 | shortID()); p2 = (byte)(offset & 0xFF); 
            
            // выполнить команду
            Response responseShort = channel.sendCommand(secureType, 
                secureClient, INS.READ_BINARY, p1, p2, new byte[0], -1
            ); 
            // при отсутствии ошибок
            if (!Response.error(responseShort))
            {
                // для последних данных
                if (responseShort.data.length < maxPart && responseShort.SW == 0x6282) 
                {
                    // изменить код завершения
                    responseShort = new Response(responseShort.data, (short)0x9000);
                } 
                // при достаточности прочитанных данных
                if (length >= 0 && responseShort.data.length >= length) 
                {
                    // изменить размер данных
                    data = Arrays.copyOf(responseShort.data, length); 

                    // вернуть результат
                    return new Response(data, responseShort.SW);
                }
                // обработать последние данные в файле
                if (responseShort.data.length < maxPart) return responseShort; 
            }
        }
        return response; 
    }
    // прочитать бинарный файл
    private Response readContentBERTLV(LogicalChannel channel, 
        int secureType, SecureClient secureClient, int offset, int length) throws IOException
    {
        // получить возможности карты
        CardCapabilities cardCapabilities = channel.environment().cardCapabilities(); 
        
        // определить максимальный размер данных
        int maxPart = (cardCapabilities.supportExtended()) ? 65536 : 256; 
        
        // закодировать объект смещения
        byte[] encoded = dataCoding().encode(new DataOffset(offset)); 
        
        // указать параметры команды
        byte p1 = 0x00; byte p2 = 0x00; byte[] data = new byte[0]; 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, 
            secureClient, INS.READ_BINARY_BERTLV, p1, p2, encoded, -1
        ); 
        // при наличии сокращенного идентификатора
        if (Response.error(response) && shortID() != null)
        {
            // выполнить команду
            p2 = shortID(); Response responseShort = channel.sendCommand(
                secureType, secureClient, INS.READ_BINARY_BERTLV, p1, p2, encoded, -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(responseShort)) response = responseShort; 
        }
        // до полного считывания данных
        while (!Response.error(response))
        {
            // для последних данных
            if (response.data.length < maxPart && response.SW == 0x6282) 
            {
                // изменить код завершения
                response = new Response(response.data, (short)0x9000);
            } 
            // раскодировать объекты
            DataObject[] objs = dataCoding().decode(response.data, true); 
            
            // проверить наличие одного объекта
            if (objs.length != 1) throw new IOException(); 
            
            // проверить тип содержимого
            if (!objs[0].tag().equals(Tag.DISCRETIONARY_DATA)) throw new IOException();
            
            // извлечь прочитанные данные
            byte[] responseData = objs[0].content(); 
            
            // изменить размер буфера
            data = Arrays.copyOf(data, data.length + responseData.length); 
                
            // скопировать прочитанные данные
            System.arraycopy(responseData, 0, data, 
                data.length - responseData.length, responseData.length
            ); 
            // при достаточности прочитанных данных
            if (length >= 0 && data.length >= length) 
            {
                // вернуть прочитанные данные
                data = Arrays.copyOf(data, length); break;
            }
            // проверить завершение данных
            if (response.data.length < maxPart) break; offset += maxPart; 
            
            // закодировать смещение
            encoded = dataCoding().encode(new DataOffset(offset));

            // выполнить команду
            response = channel.sendCommand(secureType, 
                secureClient, INS.READ_BINARY_BERTLV, p1, p2, encoded, -1
            ); 
        }
        // проверить отсутствие ошибок
        if (Response.error(response)) return response;

        // вернуть результат
        return new Response(data, response.SW); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Записать содержимое файла
    ///////////////////////////////////////////////////////////////////////////
    public Response writeContent(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        int offset, byte[] content) throws IOException
    {
        // проверить необходимость действий
        if (content.length == 0) return new Response((short)0x9000); 
        
        // записать данные
        Response response = writeContent(channel, 
            secureType, secureClient, INS.UPDATE_BINARY, offset, content
        ); 
        // проверить отсутствие ошибок
        if (!Response.error(response)) return response; 
        
        // в зависимости от типа записи
        if (dataCoding().writeEraseType() != WriteType.PROPRIETARY)
        {
            // стереть содержимое файла
            response = eraseContent(channel, 
                secureType, secureClient, offset, content.length
            ); 
            // проверить отсутствие ошибок
            if (Response.error(response)) return response; 
        }
        // записать содержимое файла
        return writeContent(channel, secureType, 
            secureClient, INS.WRITE_BINARY, offset, content
        ); 
    }
    private Response writeContent(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        byte ins, int offset, byte[] content) throws IOException
    {
        // записать данные
        Response response = writeContent0(channel, 
            secureType, secureClient, ins, offset, content
        ); 
        // проверить отсутствие ошибок
        if (!Response.error(response)) return response; 
            
        // в зависимости от кода операции
        if (ins == INS.UPDATE_BINARY) { ins = INS.UPDATE_BINARY_BERTLV; 
        
            // записать данные
            Response responseBERTLV = writeContentBERTLV(
                channel, secureType, secureClient, ins, offset, content
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(responseBERTLV)) return responseBERTLV; 
        }
        else { ins = INS.WRITE_BINARY_BERTLV; 
            
            // записать данные
            Response responseBERTLV = writeContentBERTLV(
                channel, secureType, secureClient, ins, offset, content
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(responseBERTLV)) return responseBERTLV; 
        }
        return response; 
    }
    private Response writeContent0(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        byte ins, int offset, byte[] content) throws IOException
    {
        // получить возможности карты
        CardCapabilities cardCapabilities = channel.environment().cardCapabilities(); 
        
        // определить максимальный размер данных 
        int maxPart = (cardCapabilities.supportExtended()) ? 65536 : 256; 

        // указать параметры команды
        byte p1 = (byte)((offset >>> 8) & 0xFF); byte p2 = (byte)(offset & 0xFF); 

        // при отсутствии разбиения на части
        if (cardCapabilities.supportChaining() || content.length <= maxPart)
        {
            // выполнить команду
            Response response = channel.sendCommand(
                secureType, secureClient, ins, p1, p2, content, 0
            );         
            // проверить отсутствие ошибок
            if (!Response.error(response)) return response; 
            
            // при наличии сокращенного идентификатора
            if (offset <= 255 && shortID() != null)
            {
                // указать параметры команды
                p1 = (byte)(0x80 | shortID()); p2 = (byte)(offset & 0xFF); 
            
                // выполнить команду
                Response responseShort = channel.sendCommand(
                    secureType, secureClient, ins, p1, p2, content, 0
                ); 
                // проверить отсутствие ошибок
                if (!Response.error(responseShort)) return responseShort; 
            }
            return response; 
        }
        else {
            // выделить вспомогательный буфер и скопировать данные для записи
            byte[] buffer = new byte[maxPart]; System.arraycopy(content, 0, buffer, 0, buffer.length); 

            // выполнить команду
            Response response = channel.sendCommand(
                secureType, secureClient, ins, p1, p2, buffer, 0
            );         
            // проверить отсутствие ошибок
            if (Response.error(response)) return response; 

            // проверить завершение записи
            if (buffer.length == content.length) return response; offset += buffer.length;

            // для всех оставшихся частей 
            for (int ofs = buffer.length; ofs < content.length; ofs += buffer.length, offset += buffer.length)
            {
                // указать параметры команды
                p1 = (byte)((offset >>> 8) & 0xFF); p2 = (byte)(offset & 0xFF); 

                // скорректировать размер буфера
                if (content.length - ofs < maxPart) buffer = new byte[content.length - ofs]; 

                // скопировать данные в буфер
                System.arraycopy(content, ofs, buffer, 0, buffer.length);

                // выполнить команду
                response = channel.sendCommand(secureType, secureClient, ins, p1, p2, buffer, 0);         

                // проверить отсутствие ошибок
                if (Response.error(response)) break; 
            }
            return response; 
        }
    }
    private Response writeContentBERTLV(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        byte ins, int offset, byte[] content) throws IOException
    {
        // получить возможности карты
        CardCapabilities cardCapabilities = channel.environment().cardCapabilities(); 
        
        // закодировать смещение
        byte[] encodedOffset = dataCoding().encode(new DataOffset(offset)); 
            
        // при поддержке сцепления
        if (cardCapabilities.supportChaining())
        {
            // закодировать данные
            byte[] encodedData = dataCoding().encode(new DiscretionaryData(content));
            
            // объединить объект смещения и данных
            byte[] encoded = Array.concat(encodedOffset, encodedData); 
            
            // выполнить команду
            Response response = channel.sendCommand(secureType, 
                secureClient, ins, (byte)0x00, (byte)0x00, encoded, 0
            ); 
            // при наличии сокращенного идентификатора
            if (Response.error(response) && shortID() != null)
            {
                // выполнить команду
                Response responseShort = channel.sendCommand(
                    secureType, secureClient, ins, (byte)0x00, shortID(), encoded, 0
                ); 
                // проверить отсутствие ошибок
                if (!Response.error(responseShort)) response = responseShort; 
            }
            return response; 
        }
        else {  
            // определить максимальный размер данных 
            int maxPart = (cardCapabilities.supportExtended()) ? 65536 : 256; 
        
            // при необходимости передачи по частям
            byte[] buffer = content; if (content.length > maxPart)
            {
                // выделить вспомогательный буфер и скопировать в него данные
                buffer = new byte[maxPart]; System.arraycopy(content, 0, buffer, 0, buffer.length); 
            }
            // закодировать данные
            byte[] encodedData = dataCoding().encode(new DiscretionaryData(buffer));
            
            // при превышении допустимого размера
            while (encodedOffset.length + encodedData.length > maxPart)
            {
                // переразместить буфер
                buffer = Arrays.copyOf(buffer, buffer.length - 
                    (encodedOffset.length + encodedData.length - maxPart)
                ); 
                // закодировать данные
                encodedData = dataCoding().encode(new DiscretionaryData(buffer));
            }
            // объединить объект смещения и данных
            byte[] encoded = Array.concat(encodedOffset, encodedData); byte p2 = 0x00; 
            
            // выполнить команду
            Response response = channel.sendCommand(
                secureType, secureClient, ins, (byte)0x00, p2, encoded, 0
            ); 
            
            // при наличии сокращенного идентификатора
            if (Response.error(response) && shortID() != null)
            {
                // выполнить команду
                p2 = shortID(); Response responseShort = channel.sendCommand(
                    secureType, secureClient, ins, (byte)0x00, p2, encoded, 0
                ); 
                // проверить отсутствие ошибок
                if (!Response.error(responseShort)) response = responseShort; 
            }
            // проверить отсутствие ошибок
            if (Response.error(response)) return response; 
        
            // проверить завершение записи
            if (buffer.length == content.length) return response; offset += buffer.length;
            
            // для всех частей 
            for (int ofs = buffer.length; ofs < content.length; ofs += buffer.length, offset += buffer.length)
            {
                // выделить буфер требуемого размера
                buffer = new byte[(content.length - ofs >= maxPart) ? maxPart : content.length - ofs]; 

                // скопировать данные в буфер
                System.arraycopy(content, ofs, buffer, 0, buffer.length);

                // закодировать смещение
                encodedOffset = dataCoding().encode(new DataOffset(offset)); 

                // закодировать данные
                encodedData = dataCoding().encode(new DiscretionaryData(buffer));
                
                // при превышении допустимого размера
                while (encodedOffset.length + encodedData.length > maxPart)
                {
                    // переразместить буфер
                    buffer = Arrays.copyOf(buffer, buffer.length - 
                        (encodedOffset.length + encodedData.length - maxPart)
                    ); 
                    // закодировать данные
                    encodedData = dataCoding().encode(new DiscretionaryData(buffer));
                }
                // объединить объект смещения и данных
                encoded = Array.concat(encodedOffset, encodedData); 
                
                // выполнить команду
                response = channel.sendCommand(
                    secureType, secureClient, ins, (byte)0x00, p2, encoded, 0
                );
                // проверить отсутствие ошибок
                if (Response.error(response)) break; 
            }
            return response;
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Стереть содержимое файла
    ///////////////////////////////////////////////////////////////////////////
    private Response eraseContent(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        int offset, int length) throws IOException
    {
        // проверить необходимость действий
        if (length == 0) return new Response((short)0x9000); 
        
        // указать параметры команды
        byte p1 = (byte)((offset >>> 8) & 0xFF); byte p2 = (byte)(offset & 0xFF); 
        
        // закодировать граничное смещение
        byte[] encoded = new byte[0]; if (length >= 0)
        {
            // закодировать граничное смещение
            encoded = new DataOffset(offset + length).content(); 
        }
        // выполнить команду
        Response response = channel.sendCommand(secureType, 
            secureClient, INS.ERASE_BINARY, p1, p2, encoded, 0
        ); 
        // проверить отсутствие ошибок
        if (!Response.error(response)) return response; 
        
        // при наличии сокращенного идентификатора
        if (offset <= 255 && shortID() != null)
        {
            // указать параметры команды
            p1 = (byte)(0x80 | shortID()); p2 = (byte)(offset & 0xFF); 
            
            // выполнить команду
            Response responseShort = channel.sendCommand(
                secureType, secureClient, INS.ERASE_BINARY, p1, p2, encoded, 0
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(responseShort)) return responseShort; 
        }
        // закодировать смещение
        encoded = dataCoding().encode(new DataOffset(offset)); if (length >= 0)
        {
            // закодировать граничное смещение
            byte[] encodedLimit = dataCoding().encode(new DataOffset(offset + length)); 
            
            // объединить два смещения
            encoded = Array.concat(encoded, encodedLimit); 
        }
        // выполнить команду
        Response responseBERTLV = channel.sendCommand(secureType, 
            secureClient, INS.ERASE_BINARY_BERTLV, (byte)0x00, (byte)0x00, encoded, 0
        ); 
        // при наличии сокращенного идентификатора
        if (Response.error(responseBERTLV) && shortID() != null)
        {
            // выполнить команду
            Response responseShort = channel.sendCommand(secureType, 
                secureClient, INS.ERASE_BINARY_BERTLV, (byte)0x00, shortID(), encoded, 0
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(responseShort)) responseBERTLV = responseShort; 
        }
        // проверить отсутствие ошибок
        return (!Response.error(responseBERTLV)) ? responseBERTLV : response; 
    }
}

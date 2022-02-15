package aladdin.iso7816;
import aladdin.iso7816.ber.*; 
import aladdin.asn1.*;
import aladdin.util.*; 
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Элементарный файл записей
///////////////////////////////////////////////////////////////////////////////
public class RecordFile extends ElementaryFile
{
    // конструктор
    protected RecordFile(DedicatedFile parent, short id) throws IOException
    { 
        // сохранить переданные параметры
        super(parent, id); 
    }
    // конструктор
    protected RecordFile(DedicatedFile parent, byte shortID) throws IOException
    { 
        // сохранить переданные параметры
        super(parent, shortID);
    }
    // конструктор
    protected RecordFile(DedicatedFile parent, 
        Short id, Byte shortID, FileControlInformation info) throws IOException
    { 
        // сохранить переданные параметры
        super(parent, id, shortID, info); 
    }
    // максимальный размер записи
    public final java.lang.Integer maxRecordSize() throws IOException
    {
        // получить дескриптор файла
        DataObject[] objs = info().get(Tag.context(0x02, PC.PRIMITIVE)); 
            
        // проверить наличие дескриптора
        if (objs.length == 0) return null; 

        // получить содержимое
        byte[] content = objs[0].content(); if (content.length < 3) return null; 
            
        // раскодировать значение
        if (content.length == 3) return (content[2] & 0xFF); 
        else {
            // раскодировать значение
            return ((content[2] & 0xFF) << 8) | (content[3] & 0xFF);
        }
    }
    // число записей
    public final java.lang.Integer recordCount() throws IOException
    {
        // получить дескриптор файла
        DataObject[] objs = info().get(Tag.context(0x02, PC.PRIMITIVE)); 
            
        // проверить наличие дескриптора
        if (objs.length == 0) return null; 

        // получить содержимое
        byte[] content = objs[0].content(); if (content.length < 5) return null; 
            
        // раскодировать значение
        if (content.length == 5) return (content[4] & 0xFF); 
        else {
            // раскодировать значение
            return ((content[4] & 0xFF) << 8) | (content[5] & 0xFF);
        }
    }
    // структура файла
    @Override public FileStructure fileStructure()
    {
        // получить дескриптор файла
        DataObject[] objs = info().get(Tag.context(0x02, PC.PRIMITIVE)); 
            
        // проверить наличие дескриптора
        if (objs.length == 0) return FileStructure.RECORD; 

        // получить содержимое
        byte[] content = objs[0].content(); 
        
        // проверить размер содержимого
        if (content.length < 1 || (content[0] & 0x80) != 0)
        {
            // указать значение по умолчанию
            return FileStructure.RECORD; 
        }
        // в зависимости установленных битов
        if (((content[0] >>> 3) & 0x7) != 0x7)
        {
            // в зависимости установленных битов
            switch (content[0] & 0x7)
            {
            case 0x2: return FileStructure.LINEAR_FIXED;
            case 0x3: return FileStructure.LINEAR_FIXED_TLV;
            case 0x4: return FileStructure.LINEAR_VARIABLE;
            case 0x5: return FileStructure.LINEAR_VARIABLE_TLV;
            case 0x6: return FileStructure.CYCLIC_FIXED;
            case 0x7: return FileStructure.CYCLIC_FIXED_TLV;
            }
        }
        // структура файла неизвестна
        return FileStructure.RECORD;
    }
    ///////////////////////////////////////////////////////////////////////////
    // Прочитать содержимое файла
    ///////////////////////////////////////////////////////////////////////////
    @Override public Response readContent(LogicalChannel channel, 
        int secureType, SecureClient secureClient) throws IOException
    {
        // получить возможности карты
        CardCapabilities cardCapabilities = channel.environment().cardCapabilities(); 
        
        // определить максимальный размер данных
        int maxPart = (cardCapabilities.supportExtended()) ? 65536 : 256; 
        
        // определить структуру файла
        FileStructure fileStructure = fileStructure(); 
        
        // указать направление чтения
        byte p1 = 0x01; byte p2 = (byte)(
            (fileStructure == FileStructure.CYCLIC_FIXED || 
             fileStructure == FileStructure.CYCLIC_FIXED_TLV) ? 0x06 : 0x05
        ); 
        // выполнить команду
        Response response = channel.sendCommand(secureType, 
            secureClient, INS.READ_RECORDS, p1, p2, new byte[0], -1
        ); 
        // при наличии сокращенного идентификатора
        if (Response.error(response) && shortID() != null)
        {
            // указать параметр команды
            p2 = (byte)((shortID() << 3) | p2);
            
            // выполнить команду
            Response responseShort = channel.sendCommand(secureType, 
                secureClient, INS.READ_RECORDS, p1, p2, new byte[0], -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(responseShort)) response = responseShort; 
        }
        // при отсутствии ошибок
        if (!Response.error(response))
        {
            // проверить полное считывание данных
            if (response.data.length < maxPart) return response; 
        }
        // список записей
        List<byte[]> records = new ArrayList<byte[]>(); int number = 1; 
        
        // прочитать запись
        Response responseRecord = readRecord(channel, secureType, secureClient, number); 
        
        // для всех записей
        for (; !Response.error(responseRecord); number++)
        {
            // добавить запись в список
            records.add(response.data); 

            // прочитать новую запись
            responseRecord = readRecord(channel, secureType, secureClient, number); 
        }
        // проверить кодл ошибки
        if (responseRecord.SW != 0x6A83) return response; 
        
        // объединить записи
        byte[] content = Array.concat(records.toArray(new byte[records.size()][])); 
        
        // вернуть содержимое файла
        return new Response(content, (short)0x9000); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Прочитать запись файла
    ///////////////////////////////////////////////////////////////////////////
    public byte[][] readRecords(LogicalChannel channel, 
        int secureType, SecureClient secureClient, int recordID) throws IOException
    {
        // проверить идентификатор записи
        if (recordID < 0 || recordID >= 255) throw new IllegalArgumentException(); 
        
        // создать список записей
        List<byte[]> records = new ArrayList<byte[]>(); 
        
        // для всех записей
        for (Occurence occurence = Occurence.FIRST; ; occurence = Occurence.NEXT)
        {
            // прочитать запись
            Response response = readRecord(channel, 
                secureType, secureClient, recordID, occurence
            ); 
            // добавить запись в список
            if (Response.error(response)) break; records.add(response.data);
        }
        // вернуть список записей
        return records.toArray(new byte[records.size()][]);
    }
    public Response readRecord(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        int recordID, Occurence occurence) throws IOException
    {
        // проверить идентификатор записи
        if (recordID < 0 || recordID >= 255) throw new IllegalArgumentException(); 
        
        // указать параметры команды
        byte p1 = (byte)recordID; byte p2 = (byte)occurence.value(); 
        
        // прочитать запись
        return readRecord(channel, secureType, secureClient, p1, p2); 
    }
    public Response readRecord(LogicalChannel channel, 
        int secureType, SecureClient secureClient, int number) throws IOException
    {
        // проверить номер записи
        if (number <= 0 || number >= 255) throw new IllegalArgumentException();
        
        // прочитать запись
        return readRecord(channel, secureType, secureClient, (byte)number, (byte)0x04); 
    }
    private Response readRecord(LogicalChannel channel, 
        int secureType, SecureClient secureClient, byte p1, byte p2) throws IOException
    {
        // получить возможности карты
        CardCapabilities cardCapabilities = channel.environment().cardCapabilities(); 
        
        // определить максимальный размер данных
        int maxPart = (cardCapabilities.supportExtended()) ? 65536 : 256; 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, 
            secureClient, INS.READ_RECORDS, p1, p2, new byte[0], -1
        ); 
        // при наличии сокращенного идентификатора
        if (Response.error(response) && shortID() != null)
        {
            // изменить параметр команды
            p2 = (byte)((shortID() << 3) | p2); 
            
            // выполнить команду
            Response responseShort = channel.sendCommand(secureType, 
                secureClient, INS.READ_RECORDS, p1, p2, new byte[0], -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(responseShort)) response = responseShort; 
        }
        // при отсутствии ошибок
        if (!Response.error(response))
        {
            // проверить полное считывание данных
            if (response.data.length < maxPart) return response; 
        }
        // прочитать запись полностью
        Response responseBERTLV = readRecordBERTLV(channel, secureType, secureClient, p1, p2); 
        
        // проверить отсутствие ошибок
        return (!Response.error(responseBERTLV)) ? responseBERTLV : response; 
    }
    private Response readRecordBERTLV(LogicalChannel channel, 
        int secureType, SecureClient secureClient, byte p1, byte p2) throws IOException
    {
        // получить возможности карты
        CardCapabilities cardCapabilities = channel.environment().cardCapabilities(); 
        
        // определить максимальный размер данных
        int maxPart = (cardCapabilities.supportExtended()) ? 65536 : 256; 
        
        // указать начальные условия
        byte[] data = new byte[0]; int offset = 0; 
        
        // закодировать объект смещения
        byte[] encoded = dataCoding().encode(new DataOffset(offset)); 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, 
            secureClient, INS.READ_RECORDS_BERTLV, p1, p2, encoded, -1
        ); 
        // при наличии сокращенного идентификатора
        if (Response.error(response) && shortID() != null)
        {
            // изменить параметр команды
            p2 = (byte)((shortID() << 3) | p2); 
            
            // выполнить команду
            Response responseShort = channel.sendCommand(secureType, 
                secureClient, INS.READ_RECORDS_BERTLV, p1, p2, encoded, -1
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
            // обработать последние данные в файле
            if (response.data.length < maxPart) break; offset += maxPart; 

            // изменить смещение
            encoded = dataCoding().encode(new DataOffset(offset));

            // выполнить команду
            response = channel.sendCommand(secureType, 
                secureClient, INS.READ_RECORDS_BERTLV, p1, p2, encoded, -1
            ); 
        }
        // проверить отсутствие ошибок
        if (Response.error(response)) return response; 
        
        // вернуть прочитанные данные
        return new Response(data, response.SW);
    }
    ///////////////////////////////////////////////////////////////////////////
    // Записать запись файла
    ///////////////////////////////////////////////////////////////////////////
    public Response writeRecord(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        int number, byte[] content) throws IOException
    {
        // проверить номер записи
        if (number <= 0 || number >= 255) throw new IllegalArgumentException();
        
        // записать запись файла
        Response response = writeRecord(channel, secureType, 
            secureClient, INS.UPDATE_RECORD, (byte)number, (byte)0x04, content
        ); 
        // проверить отсутствие ошибок
        if (!Response.error(response)) return response; 
        
        // в зависимости от типа записи
        if (dataCoding().writeEraseType() != WriteType.PROPRIETARY)
        {
            // стереть запись файла
            response = eraseRecord(channel, secureType, secureClient, number); 
            
            // проверить отсутствие ошибок
            if (Response.error(response)) return response; 
        }
        // записать запись файла
        return writeRecord(channel, secureType, 
            secureClient, INS.WRITE_RECORD, (byte)number, (byte)0x04, content
        ); 
    }
    private Response writeRecord(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        byte ins, byte p1, byte p2, byte[] content) throws IOException
    {
        // получить возможности карты
        CardCapabilities cardCapabilities = channel.environment().cardCapabilities(); 
        
        // определить максимальный размер данных 
        int maxPart = (cardCapabilities.supportExtended()) ? 65536 : 256; 
        
        // при разбиении на части
        if (!cardCapabilities.supportChaining() && content.length > maxPart)
        {
            // проверить код операции
            if (ins != INS.UPDATE_RECORD) return new Response((short)0x6A81); 
        
            // записать запись файла
            return writeRecordBERTLV(channel, secureType, 
                secureClient, INS.UPDATE_RECORD_BERTLV, p1, p2, 0, content
            ); 
        }
        else {
            // выполнить команду
            Response response = channel.sendCommand(
                secureType, secureClient, ins, p1, p2, content, 0
            ); 
            // при наличии сокращенного идентификатора
            if (Response.error(response) && shortID() != null)
            {
                // изменить код команды
                p2 = (byte)((shortID() << 3) | p2); 
                
                // выполнить команду
                Response responseShort = channel.sendCommand(
                    secureType, secureClient, ins, p1, p2, content, 0
                ); 
                // проверить отсутствие ошибок
                if (!Response.error(responseShort)) response = responseShort; 
            }
            // проверить отсутствие ошибок
            if (!Response.error(response) || ins != INS.UPDATE_RECORD) return response; 
            
            // записать запись файла
            Response responseBERTLV = writeRecordBERTLV(channel, 
                secureType, secureClient, INS.UPDATE_RECORD_BERTLV, p1, p2, 0, content
            ); 
            // проверить отсутствие ошибок
            return (!Response.error(responseBERTLV)) ? responseBERTLV : response; 
        }
    }
    private Response writeRecordBERTLV(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        byte ins, byte p1, byte p2, int offset, byte[] content) throws IOException
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
            Response response = channel.sendCommand(
                secureType, secureClient, ins, p1, p2, encoded, 0
            ); 
            // при наличии сокращенного идентификатора
            if (Response.error(response) && shortID() != null)
            {
                // выполнить команду
                Response responseShort = channel.sendCommand(
                    secureType, secureClient, ins, p1, shortID(), encoded, 0
                ); 
                // проверить отсутствие ошибок
                if (!Response.error(responseShort)) response = responseShort; 
            }
            return response; 
        }
        else {
            // определить максимальный размер данных 
            int maxPart = (cardCapabilities.supportExtended()) ? 65536 : 256; 

            // при необходимости разбиения на части
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
            byte[] encoded = Array.concat(encodedOffset, encodedData); 

            // выполнить команду
            Response response = channel.sendCommand(
                secureType, secureClient, ins, p1, p2, encoded, 0
            ); 
            // при наличии сокращенного идентификатора
            if (Response.error(response) && shortID() != null)
            {
                // изменить параметр команды
                p2 = (byte)((shortID() << 3) | p2); 

                // выполнить команду
                Response responseShort = channel.sendCommand(
                    secureType, secureClient, ins, p1, p2, encoded, 0
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
                    secureType, secureClient, ins, p1, p2, encoded, 0
                );
                // проверить отсутствие ошибок
                if (Response.error(response)) break; 
            }
            return response;
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Стереть записи
    ///////////////////////////////////////////////////////////////////////////
    public Response eraseRecord(LogicalChannel channel, 
        int secureType, SecureClient secureClient, int number) throws IOException
    {
        // проверить номер записи
        if (number <= 0 || number >= 255) throw new IllegalArgumentException();
        
        // указать параметры команды
        byte p1 = (byte)number; byte p2 = 0x04; 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, 
            secureClient, INS.ERASE_RECORDS, p1, p2, new byte[0], 0
        ); 
        // при наличии сокращенного идентификатора
        if (Response.error(response) && shortID() != null)
        {
            // изменить параметр команды
            p2 = (byte)((shortID() << 3) | p2); 
            
            // выполнить команду
            Response responseShort = channel.sendCommand(secureType, 
                secureClient, INS.ERASE_RECORDS, p1, p2, new byte[0], 0
            ); 
            // проверить отсут ствие ошибок
            if (!Response.error(responseShort)) response = responseShort; 
        }
        return response; 
    }
    public Response eraseRecords(LogicalChannel channel, 
        int secureType, SecureClient secureClient, int fromNumber) throws IOException
    {
        // проверить номер записи
        if (fromNumber <= 0 || fromNumber >= 255) throw new IllegalArgumentException();
        
        // указать параметры команды
        byte p1 = (byte)fromNumber; byte p2 = 0x05; 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, 
            secureClient, INS.ERASE_RECORDS, p1, p2, new byte[0], 0
        ); 
        // при наличии сокращенного идентификатора
        if (Response.error(response) && shortID() != null)
        {
            // изменить параметр команды
            p2 = (byte)((shortID() << 3) | p2); 
            
            // выполнить команду
            Response responseShort = channel.sendCommand(secureType, 
                secureClient, INS.ERASE_RECORDS, p1, p2, new byte[0], 0
            ); 
            // проверить отсут ствие ошибок
            if (!Response.error(responseShort)) response = responseShort; 
        }
        return response; 
    }
}

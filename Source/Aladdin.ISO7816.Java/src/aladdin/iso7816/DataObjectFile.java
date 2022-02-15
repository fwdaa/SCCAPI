package aladdin.iso7816;
import aladdin.iso7816.ber.*; 
import aladdin.asn1.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Элементарный файл объектов
///////////////////////////////////////////////////////////////////////////////
public class DataObjectFile extends ElementaryFile
{
    // конструктор
    protected DataObjectFile(DedicatedFile parent, short id) throws IOException
    { 
        // сохранить переданные параметры
        super(parent, id); 
    }
    // конструктор
    protected DataObjectFile(DedicatedFile parent, byte shortID) throws IOException
    { 
        // сохранить переданные параметры
        super(parent, shortID);
    }
    // конструктор
    protected DataObjectFile(DedicatedFile parent, 
        Short id, Byte shortID, FileControlInformation info) throws IOException
    { 
        // сохранить переданные параметры
        super(parent, id, shortID, info); 
    }
    // структура файла
    @Override public FileStructure fileStructure()
    {
        // получить дескриптор файла
        DataObject[] objs = info().get(Tag.context(0x02, PC.PRIMITIVE)); 
            
        // проверить наличие дескриптора
        if (objs.length == 0) return FileStructure.DATA_OBJECT; 

        // получить содержимое
        byte[] content = objs[0].content(); 
        
        // проверить размер содержимого
        if (content.length < 1 || (content[0] & 0x80) != 0)
        {
            // указать значение по умолчанию
            return FileStructure.DATA_OBJECT; 
        }
        // в зависимости установленных битов
        if (((content[0] >>> 3) & 0x7) == 0x7)
        {
            // в зависимости установленных битов
            switch (content[0] & 0x7)
            {
            case 0x1: return FileStructure.DATA_OBJECT_BERTLV;
            case 0x2: return FileStructure.DATA_OBJECT_SIMPLETLV;
            }
        }
        // структура файла неизвестна
        return FileStructure.DATA_OBJECT;
    }
    // выделить родительский каталог
    @Override public DedicatedFile selectParent(LogicalChannel channel) throws IOException
    {
        // выделить родительский каталог
        parent().selectFromChild(channel); return parent(); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // прочитать содержимое файла
    ///////////////////////////////////////////////////////////////////////////
    @Override public Response readContent(LogicalChannel channel, 
        int secureType, SecureClient secureClient) throws IOException
    {
        // выполнить команду
        Response response = channel.sendCommand(secureType, 
            secureClient, INS.GET_DATA, (byte)0x00, (byte)0x00, new byte[0], -1
        ); 
        // проверить отсутствие ошибок
        if (!Response.error(response)) return response; 
            
        // закодировать список тэгов
        byte[] encoded = dataCoding().encode(new TagList()); 
        
        // выполнить команду
        Response responseBERTLV = channel.sendCommand(secureType, 
            secureClient, INS.GET_DATA_BERTLV, (byte)0x00, (byte)0x00, encoded, -1
        ); 
        // при наличии сокращенного идентификатора
        if (Response.error(responseBERTLV) && shortID() != null)
        {
            // выполнить команду
            Response responseShort = channel.sendCommand(secureType, 
                secureClient, INS.GET_DATA_BERTLV, (byte)0x00, shortID(), encoded, -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(responseShort)) responseBERTLV = responseShort; 
        }
        // проверить отсутствие ошибок
        return (!Response.error(responseBERTLV)) ? responseBERTLV : response; 
    }
    // прочитать файл объектов
    public DataObject[] readBERTLVs(LogicalChannel channel, 
        int secureType, SecureClient secureClient, boolean interindustry) throws IOException
    {
        // определить структуру файла
        FileStructure fileStructure = fileStructure(); 
        
        // для файла записей и файла объектов
        if (fileStructure != FileStructure.DATA_OBJECT && 
            fileStructure != FileStructure.DATA_OBJECT_BERTLV)
        {
            // при ошибке выбросить исключение
            throw new ResponseException((short)0x6981); 
        }
        // прочитать содержимое файла
        Response response = readContent(channel, secureType, secureClient); 
        
        // проверить отсутствие ошибок
        ResponseException.check(response);
        
        // раскодировать объекты
        return dataCoding().decode(response.data, interindustry); 
    }
    // прочитать файл объектов
    public SimpleTLV[] readSimpleTLVs(LogicalChannel channel, 
        int secureType, SecureClient secureClient) throws IOException
    {
        // определить структуру файла
        FileStructure fileStructure = fileStructure(); 
        
        // для файла записей и файла объектов
        if (fileStructure != FileStructure.DATA_OBJECT && 
            fileStructure != FileStructure.DATA_OBJECT_SIMPLETLV)
        {
            // при ошибке выбросить исключение
            throw new ResponseException((short)0x6981); 
        }
        // прочитать содержимое файла
        Response response = readContent(channel, secureType, secureClient); 
        
        // проверить отсутствие ошибок
        ResponseException.check(response);
        
        // раскодировать объекты
        return SimpleTLV.decode(response.data); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // прочитать объекты
    ///////////////////////////////////////////////////////////////////////////
    public SimpleTLV readObject(LogicalChannel channel, 
        int secureType, SecureClient secureClient, int tag) throws IOException
    {
        // проверить корректноть тэга
        if (tag < 0 || tag > 255) throw new IllegalArgumentException(); 

        // выполнить команду
        Response response = channel.sendCommand(secureType, 
            secureClient, INS.GET_DATA, (byte)0x02, (byte)tag, new byte[0], -1
        ); 
        // проверить отсутствие ошибок
        ResponseException.check(response);
        
        // проверить наличие данных
        if (response.data.length == 0) return null; 

        // раскодировать объект
        return SimpleTLV.decode(response.data)[0]; 
    }
    // прочитать объект
    public DataObject readObject(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        Tag tag, boolean interindustry) throws IOException
    {
        // закодировать тэг
        byte[] encoded = tag.encoded; if (encoded.length == 1)
        {
            // выполнить команду
            Response response = channel.sendCommand(secureType, 
                secureClient, INS.GET_DATA, (byte)0x00, encoded[0], new byte[0], -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(response))
            {
                // проверить наличие данных
                if (response.data.length == 0) return null; 

                // раскодировать объект
                return dataCoding().decode(encoded, interindustry)[0]; 
            }
        }
        else if (encoded.length == 2)
        {
            // выполнить команду
            Response response = channel.sendCommand(secureType, 
                secureClient, INS.GET_DATA, encoded[0], encoded[1], new byte[0], -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(response))
            {
                // проверить наличие данных
                if (response.data.length == 0) return null; 

                // раскодировать объект
                return dataCoding().decode(encoded, interindustry)[0]; 
            }
        }
        // прочитать объекты
        return readObjects(channel, secureType, 
            secureClient, new Tag[] { tag }, interindustry)[0];
    }
    // прочитать объекты
    public DataObject[] readObjects(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        Tag[] tags, boolean interindustry) throws IOException
    {
        // закодировать список тэгов
        byte[] encoded = dataCoding().encode(new TagList(tags)); 

        // выполнить команду
        Response response = channel.sendCommand(secureType, 
            secureClient, INS.GET_DATA_BERTLV, (byte)0x00, (byte)0x00, encoded, -1
        ); 
        // при наличии сокращенного идентификатора
        if (Response.error(response) && shortID() != null)
        {
            // выполнить команду
            Response responseShort = channel.sendCommand(secureType, 
                secureClient, INS.GET_DATA_BERTLV, (byte)0x00, shortID(), encoded, -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(responseShort)) response = responseShort; 
        }
        // проверить отсутствие ошибок
        ResponseException.check(response); 
        
        // раскодировать объекты
        return dataCoding().decode(response.data, interindustry); 
    }
    // прочитать объекты
    public DataObject[] readObjects(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        Header[] headers, boolean interindustry) throws IOException
    {
        // закодировать список заголовков
        byte[] encoded = dataCoding().encode(new HeaderList(headers)); 

        // выполнить команду
        Response response = channel.sendCommand(secureType, 
            secureClient, INS.GET_DATA_BERTLV, (byte)0x00, (byte)0x00, encoded, -1
        ); 
        // при наличии сокращенного идентификатора
        if (Response.error(response) && shortID() != null)
        {
            // выполнить команду
            Response responseShort = channel.sendCommand(secureType, 
                secureClient, INS.GET_DATA_BERTLV, (byte)0x00, shortID(), encoded, -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(responseShort)) response = responseShort; 
        }
        // проверить отсутствие ошибок
        ResponseException.check(response); 
        
        // раскодировать объекты
        return dataCoding().decode(response.data, interindustry); 
    }
    // прочитать объекты
    public DataObject[] readObjects(LogicalChannel channel, 
        int secureType, SecureClient secureClient, 
        ExtendedHeader[] extendedHeaders, boolean interindustry) throws IOException 
    {
        // закодировать список заголовков
        byte[] encoded = dataCoding().encode(new ExtendedHeaderList(extendedHeaders)); 

        // выполнить команду
        Response response = channel.sendCommand(secureType, 
            secureClient, INS.GET_DATA_BERTLV, (byte)0x00, (byte)0x00, encoded, -1
        ); 
        // при наличии сокращенного идентификатора
        if (Response.error(response) && shortID() != null)
        {
            // выполнить команду
            Response responseShort = channel.sendCommand(secureType, 
                secureClient, INS.GET_DATA_BERTLV, (byte)0x00, shortID(), encoded, -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(responseShort)) response = responseShort; 
        }
        // проверить отсутствие ошибок
        ResponseException.check(response); 
        
        // раскодировать объекты
        return dataCoding().decode(response.data, interindustry); 
    }
}

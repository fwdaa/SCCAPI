package aladdin.iso7816;
import aladdin.iso7816.ber.*;
import aladdin.asn1.*; 
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Каталог файлов
///////////////////////////////////////////////////////////////////////////////
public class DedicatedFile extends File
{
    // выделить каталог по имени
    public static DedicatedFile select(LogicalChannel channel, byte[] name) throws IOException
    {
        // указать начальные условия
        Response response = new Response(new byte[0], (short)0x6A81); 

        // получить возможности смарт-карты
        CardCapabilities cardCapabilities = channel.environment().cardCapabilities(); 

        // проверить возможность выбора по имени
        if ((cardCapabilities.data(0) & 0x80) == 0) ResponseException.check(response); 
        
        // список информации файлов
        List<byte[]> infos = new ArrayList<byte[]>(); 
        
        // выбрать файл по имени
        response = channel.sendCommand(INS.SELECT, (byte)0x04, (byte)0x00, name, -1); 
        
        // проверить отсутствие ошибок
        ResponseException.check(response); infos.add(response.data);
        
        // при возможности выбора по идентификатору
        if ((cardCapabilities.data(0) & 0x10) != 0)
        {
            // для всех родительских каталогов
            while (!Response.error(response))
            {
                // выбрать родительский каталог
                response = channel.sendCommand(
                    INS.SELECT, (byte)0x03, (byte)0x00, new byte[0], -1
                );
                // добавить информацию в список
                infos.add(response.data);
            }
        }
        // указать способ кодирования
        DataCoding dataCoding = channel.environment().dataCoding(); DedicatedFile dedicatedFile = null;
        
        // для всех родительских каталогов
        for (int i = infos.size() - 1; i > 0; i--)
        {
            // получить описание каталога
            FileControlInformation info = FileControlInformation.decode(dataCoding, infos.get(i)); 
            
            // получить имя каталога
            DataObject[] objs = info.get(Tag.context(0x04, PC.PRIMITIVE)); if (objs.length != 0)
            {
                // извлечь имя каталога
                byte[] fileName = objs[0].content(); 
                    
                // выбрать файл по имени
                response = channel.sendCommand(INS.SELECT, (byte)0x04, (byte)0x0C, fileName, 0); 
                
                // проверить отсутствие ошибок
                if (Response.error(response)) { dedicatedFile = null; break; } 
                
                // при отсутствии родительского каталога
                if (dedicatedFile == null)
                {
                    // создать объект каталога
                    dedicatedFile = new DedicatedFile(fileName, dataCoding, info); 

                    // прочитать дополнительную информацию
                    info = info.сombine(dedicatedFile.readInfoExtension(channel)); 
                    
                    // создать объект каталога
                    dedicatedFile = new DedicatedFile(fileName, dataCoding, info); 
                }
                else {
                    // создать объект каталога
                    dedicatedFile = new DedicatedFile(dedicatedFile, fileName, info); 

                    // прочитать дополнительную информацию
                    info = info.сombine(dedicatedFile.readInfoExtension(channel)); 

                    // создать объект каталога
                    dedicatedFile = new DedicatedFile(dedicatedFile, fileName, info); 
                }
            }
            else {
                // проверить наличие идентификатора
                Short id = info.id(); if (id == null) { dedicatedFile = null; break; }

                // указать идентификатор файла
                byte[] encodedID = new byte[] { (byte)((id >>> 8) & 0xFF), (byte)(id & 0xFF) }; 
                
                // выбрать файл по идентификатору
                response = channel.sendCommand(INS.SELECT, (byte)0x01, (byte)0x0C, encodedID, 0); 
                
                // проверить отсутствие ошибок
                if (Response.error(response)) { dedicatedFile = null; break; } 
                
                // при отсутствии родительского каталога
                if (dedicatedFile == null)
                {
                    // создать объект каталога
                    dedicatedFile = new DedicatedFile(id, dataCoding, info); 

                    // прочитать дополнительную информацию
                    info = info.сombine(dedicatedFile.readInfoExtension(channel)); 
                    
                    // создать объект каталога
                    dedicatedFile = new DedicatedFile(id, dataCoding, info); 
                }
                else {
                    // создать объект каталога
                    dedicatedFile = new DedicatedFile(dedicatedFile, id, info); 

                    // прочитать дополнительную информацию
                    info = info.сombine(dedicatedFile.readInfoExtension(channel)); 
                    
                    // создать объект каталога
                    dedicatedFile = new DedicatedFile(dedicatedFile, id, info); 
                }
            }
            // изменить способ кодирования данных
            dataCoding = info.getDataCoding(dataCoding); 
        }{
            // получить описание каталога
            FileControlInformation info = FileControlInformation.decode(dataCoding, infos.get(0)); 
            
            if (infos.size() > 1)
            {
                // выбрать файл по имени
                response = channel.sendCommand(INS.SELECT, (byte)0x04, (byte)0x0C, name, 0); 
                
                // проверить отсутствие ошибок
                ResponseException.check(response);
            }
            // при отсутствии родительского каталога
            if (dedicatedFile == null) 
            {
                // создать объект каталога
                dedicatedFile = new DedicatedFile(name, dataCoding, info);

                // прочитать дополнительную информацию
                info = info.сombine(dedicatedFile.readInfoExtension(channel)); 

                // создать объект каталога
                dedicatedFile = new DedicatedFile(name, dataCoding, info);
            }
            else {
                // создать объект каталога
                dedicatedFile = new DedicatedFile(dedicatedFile, name, info); 

                // прочитать дополнительную информацию
                info = info.сombine(dedicatedFile.readInfoExtension(channel)); 

                // создать объект каталога
                dedicatedFile = new DedicatedFile(dedicatedFile, name, info); 
            }
        }
        return dedicatedFile;
    }
    // выделить каталог по пути
    public static DedicatedFile select(LogicalChannel channel, short[] path) throws IOException
    {
        // проверить наличие пути
        if (path == null || path.length == 0) throw new IllegalArgumentException(); 
        
        // проверить корневой элемент
        if (path[0] != 0x3F00) throw new IllegalArgumentException(); byte[] responseData = null;

        // выбрать мастер-файл
        Response response = channel.sendCommand( 
            INS.SELECT, (byte)0x00, (byte)0x00, new byte[0], -1
        ); 
        // проверить отсутствие ошибок
        if (!Response.error(response)) responseData = response.data;
        
        // получить возможности смарт-карты
        CardCapabilities cardCapabilities = channel.environment().cardCapabilities(); 

        // при возможности выбора по идентификатору
        if (responseData != null && ((cardCapabilities.data(0) & 0x10) != 0))
        {
            // выбрать мастер-файл
            response = channel.sendCommand(
                INS.SELECT, (byte)0x00, (byte)0x00, new byte[] { 0x3F, 0x00 }, -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(response)) responseData = response.data;
        }
        // при возможности выбора по пути
        if (responseData != null && ((cardCapabilities.data(0) & 0x20) != 0))
        {
            // выбрать мастер-файл
            response = channel.sendCommand(
                INS.SELECT, (byte)0x08, (byte)0x00, new byte[0], -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(response)) responseData = response.data;
        }
        // при ошибке выбросить исключение
        if (responseData == null) ResponseException.check(response); 
        
        // указать способ кодирования
        DataCoding dataCoding = channel.environment().dataCoding(); 
        
        // получить описание каталога
        FileControlInformation info = FileControlInformation.decode(dataCoding, responseData); 
        
        // создать объект мастер-файла
        DedicatedFile dedicatedFile = new DedicatedFile(path[0], dataCoding, info); 
        
        // прочитать дополнительную информацию
        info = info.сombine(dedicatedFile.readInfoExtension(channel)); 
        
        // создать объект мастер файла
        dedicatedFile = new DedicatedFile(path[0], dataCoding, info); 
        
        // для всех внутренних каталогов
        for (int i = 1; i < path.length; i++)
        {
            // выбрать внутренний каталог
            dedicatedFile = dedicatedFile.selectDedicatedFile(channel, path[i]); 
        }
        return dedicatedFile; 
    }
    // конструктор
    private DedicatedFile(short id, 
        DataCoding dataCoding, FileControlInformation info) throws IOException
    {
        // сохранить переданные параметры
        super(id, dataCoding, info); 
        
        // получить имя каталога
        DataObject[] objs = info.get(Tag.context(0x04, PC.PRIMITIVE)); 
        
        // сохранить имя каталога
        this.name = (objs.length != 0) ? objs[0].content() : null; 
    }
    // конструктор
    private DedicatedFile(byte[] name, 
        DataCoding dataCoding, FileControlInformation info) throws IOException
    {
        // сохранить переданные параметры
        super(info.id(), dataCoding, info); this.name = name; 
    }
    // конструктор
    private DedicatedFile(DedicatedFile parent, 
        short id, FileControlInformation info) throws IOException
    {
        // сохранить переданные параметры
        super(parent, id, info); 
        
        // получить имя каталога
        DataObject[] objs = info.get(Tag.context(0x04, PC.PRIMITIVE)); 
        
        // сохранить имя каталога
        this.name = (objs.length != 0) ? objs[0].content() : null; 
    }
    // конструктор
    private DedicatedFile(DedicatedFile parent, 
        byte[] name, FileControlInformation info) throws IOException
    {
        // сохранить переданные параметры
        super(parent, info.id(), info); this.name = name; 
    }
    // имя каталога
    public final byte[] name() { return name; } private final byte[] name;
    
    // выделить каталог при выделенном дочернем файле
    protected void selectFromChild(LogicalChannel channel) throws IOException
    {
        // при наличии идентификатора
        if (id() != null && parent() == null)
        {
            // выбрать каталог по идентификатору
            DedicatedFile.select(channel, new short[] { id() } ); 
        }
        // при наличии идентификатора
        else if (id() != null && parent() != null)
        {
            // выбрать каталог по идентификатору
            parent().selectDedicatedFile(channel, id()); 
        }
        else {
            // выбрать каталог по имени
            Response response = channel.sendCommand(
                INS.SELECT, (byte)0x04, (byte)0x0C, name, 0
            ); 
            // проверить отсутствие ошибок
            ResponseException.check(response);
        }
    }
    // прочитать дополнительную информацию
    private DataObjectTemplate readInfoExtension(LogicalChannel channel) throws IOException
    {
        // получить идентификатор файла с дополнительной информацией
        DataObject[] objs = info().get(Tag.context(0x07, PC.PRIMITIVE)); 
        
        // проверить наличие файла
        if (objs.length == 0) return null; byte[] content = objs[0].content();
        
        // проверить размер идентификатора
        if (content.length != 2) return null; 
        
        // раскодировать идентификатор файла
        short fileID = (short)((content[0] << 8) | content[1]); 
        
        // прочитать файл объектов
        Response response = readDataObjectFile(channel, fileID, SecureType.NONE, null); 
        
        // проверить отсутствие ошибок
        ResponseException.check(response); 
                
        // для всех объектов
        for (DataObject obj : dataCoding().decode(response.data, true))
        {
            // проверить тип объекта
            if (obj.tag().equals(Tag.FILE_CONTROL_INFORMATION))
            {
                // выполнить преобразование типа
                return new FileControlInformation(dataCoding().tagScheme(), obj.content()); 
            }
            // проверить тип объекта
            if (obj.tag().equals(Tag.FILE_CONTROL_PARAMETERS))
            {
                // выполнить преобразование типа
                return new FileControlParameters(dataCoding().tagScheme(), obj.content()); 
            }
        }
        return null; 
    }
    // выделить родительский каталог
    @Override public DedicatedFile selectParent(LogicalChannel channel) throws IOException
    {
        // проверить наличие родительского каталога
        if (parent() == null) return null; DataCoding parentCoding = channel.environment().dataCoding(); 
        
        // указать способ кодирования
        if (parent().parent() != null) parentCoding = parent().parent().dataCoding(); 
        
        // указать начальные условия
        Response response = new Response(new byte[0], (short)0x6A81); byte[] responseData = null; 
        
        // получить возможности смарт-карты
        CardCapabilities cardCapabilities = channel.environment().cardCapabilities(); 

        // при возможности выбора по идентификатору
        if (responseData == null && (cardCapabilities.data(0) & 0x10) != 0)
        {
            // выбрать родительский каталог
            response = channel.sendCommand(
                INS.SELECT, (byte)0x03, (byte)0x00, new byte[0], -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(response)) responseData = response.data; 
        }
        // при возможности выбора по пути
        if (responseData == null && (cardCapabilities.data(0) & 0x20) != 0 && parent().path() != null)
        {
            // выделить память для сокращенного пути
            short[] path = parent().path(); byte[] encodedPath = new byte[(path.length - 1) * 2]; 

            // для всех компонентов пути
            for (int i = 1; i < path.length; i++)
            {
                // закодировать компонент пути
                encodedPath[2 * i - 2] = (byte)((path[i] >>> 8) & 0xFF); 
                encodedPath[2 * i - 1] = (byte) (path[i]        & 0xFF); 
            }
            // выбрать каталог по пути
            response = channel.sendCommand(
                INS.SELECT, (byte)0x08, (byte)0x00, encodedPath, -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(response)) responseData = response.data; 
        }
        // при возможности выбора по имени
        if (responseData == null && (cardCapabilities.data(0) & 0x80) != 0 && parent().name() != null)
        {
            // выбрать каталог по имени
            response = channel.sendCommand(
                INS.SELECT, (byte)0x04, (byte)0x0C, parent().name(), 0
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(response)) responseData = response.data;
        }
        // проверить отсутствие ошибок
        if (responseData == null) ResponseException.check(response);
        
        // получить описание каталога
        FileControlInformation info = FileControlInformation.decode(parentCoding, response.data); 
        
        // прочитать дополнительную информацию
        info = info.сombine(parent().readInfoExtension(channel)); if (parent().id() != null)
        {
            // вернуть объект родительского каталога
            return new DedicatedFile(parent().parent(), parent().id(), info); 
        }
        else {
            // вернуть объект родительского каталога
            return new DedicatedFile(parent().parent(), parent().name(), info); 
        }
    }
    // выделить каталог или файл
    public File selectFile(LogicalChannel channel, 
        FileReference reference, FileStructure fileStructure) throws IOException
    {
        // указать начальные условия 
        ResponseException exception = new ResponseException((short)0x6981); 
        
        // для мастер-файла
        if (reference.content().length == 0) 
        {
            // проверить корректность параметров
            if (fileStructure != FileStructure.UNKNOWN) throw exception; 
            
            // выделить мастер-файл
            return DedicatedFile.select(channel, reference.path());
        } 
        // при указании сокращенного идентификатора
        if (reference.content().length == 1)
        {
            // выделить элементарный файл
            return selectElementaryFile(channel, reference.shortID(), fileStructure); 
        }
        // при указании идентификатора
        if (reference.content().length == 2) 
        { 
            // для мастре-файла
            short id = reference.id(); if (id == 0x3F00) { 
                
                // проверить корректность параметров
                if (fileStructure != FileStructure.UNKNOWN) throw exception; 
                
                // выделить мастер-файл
                return DedicatedFile.select(channel, reference.path());
            } 
            // вернуть текущимй файл
            if (id == 0x3FFF) 
            {
                // проверить корректность параметров
                if (fileStructure != FileStructure.UNKNOWN) throw exception; 
                
                return this;
            } 
            // выделить файл
            try { return selectElementaryFile(channel, id, fileStructure); }

            // при возникновении ошибки
            catch (ResponseException e) { if (e.SW != 0x6981) throw e;
             
                // проверить корректность параметров
                if (fileStructure != FileStructure.UNKNOWN) throw exception; 
                
                // выделить каталог
                return selectDedicatedFile(channel, id); 
            }
        }
        // указать начальные условия
        short[] path = reference.path(); int type = -1;
        
        // при указании только пути
        if ((reference.content().length % 2) == 0) 
        { 
            // при указании идентификатора каталога
            if (path[0] != 0x3F00 && path[0] != 0x3FFF) 
            { 
                // проверить совпадение идентификатора
                if (path[0] != id()) throw new IllegalStateException(); path[0] = 0x3FFF;
            }
        }
        // для абсолютного пути
        else if (reference.p1() == 0x08) 
        {
            // изменить размер буфера
            path = Arrays.copyOf(path, path.length + 1); 
            
            // сместить путь 
            System.arraycopy(path, 0, path, 1, path.length - 1); path[0] = 0x3F00;
        }
        // для относительного пути
        else if (reference.p1() == 0x09)
        {
            // изменить размер буфера
            path = Arrays.copyOf(path, path.length + 1); 
            
            // сместить путь 
            System.arraycopy(path, 0, path, 1, path.length - 1); path[0] = 0x3FFF;
        }
        // для относительного пути каталога
        else if (reference.p1() == 0x01)
        {
            // изменить размер буфера
            path = Arrays.copyOf(path, path.length + 1); type = 0; 
            
            // сместить путь 
            System.arraycopy(path, 0, path, 1, path.length - 1); path[0] = 0x3FFF;
        }
        // для относительного пути файла
        else if (reference.p1() == 0x02)
        {
            // проверить отсутствие ошибок
            if (reference.content().length != 3) throw new IllegalStateException(); 
            
            // изменить размер буфера
            path = Arrays.copyOf(path, path.length + 1); type = 1; 
            
            // сместить путь 
            System.arraycopy(path, 0, path, 1, path.length - 1); path[0] = 0x3FFF;
        }
        // обработать возможную ошибку
        else throw new UnsupportedOperationException(); 
        
        // указать начальные условия 
        DedicatedFile dedicatedFile = this; int i = 1; 
        
        // для абсолютного пути
        if (path[0] == 0x3F00)
        {
            // список родительских каталогов
            List<DedicatedFile> dedicatedFiles = new ArrayList<DedicatedFile>(); 
                
            // для всех родительских каталогов
            for (; dedicatedFile != null; dedicatedFile = dedicatedFile.parent())
            {
                // сохранить родительский каталог
                dedicatedFiles.add(dedicatedFile); 
            }
            // для всех компонентов пути
            for (i = 0, dedicatedFile = null; i < path.length; i++)
            {
                // проверить наличие каталога
                if (dedicatedFiles.size() <= i) break; 
                    
                // получить каталог
                DedicatedFile nextFile = dedicatedFiles.get(dedicatedFiles.size() - 1 - i); 
                    
                // проверить совпадение идентификаторов
                if (path[i] != nextFile.id()) break; dedicatedFile = nextFile; 
            }
            // выбрать каталог по абсолютному пути
            if (dedicatedFile == null) return DedicatedFile.select(channel, path);
                
            // для всех родительских каталогов
            for (DedicatedFile parent = this; parent != dedicatedFile; )
            {
                // выделить родительский каталог
                parent = parent.selectParent(channel); 
            }
            // проверить достижение файла
            if (i == path.length) return dedicatedFile; 
        }
        // для всех каталогов
        for (; i < path.length - 1; i++)
        {
            // выбрать внутренний каталог
            dedicatedFile = dedicatedFile.selectDedicatedFile(channel, path[i]); 
        }
        switch (type)
        {
        case 0: {
            // проверить корректность параметров
            if (fileStructure != FileStructure.UNKNOWN) throw exception; 
            
            // выделить каталог
            return dedicatedFile.selectDedicatedFile(channel, path[path.length - 1]); 
        }
        case 1: {
            // выделить файл
            return dedicatedFile.selectElementaryFile(
                channel, path[path.length - 1], fileStructure
            ); 
        }
        default: 
            try { 
                // выделить файл
                return dedicatedFile.selectElementaryFile(
                    channel, path[path.length - 1], fileStructure
                ); 
            }
            // при возникновении ошибки
            catch (ResponseException e) { if (e.SW != 0x6981) throw e;
            
                // проверить корректность параметров
                if (fileStructure != FileStructure.UNKNOWN) throw exception; 
                
                // выделить каталог
                return dedicatedFile.selectDedicatedFile(channel, path[path.length - 1]); 
            }
        }
    }
    // выделить дочерний каталог
    public DedicatedFile selectDedicatedFile(LogicalChannel channel, short id) throws IOException
    {
        // указать начальные условия
        Response response = new Response(new byte[0], (short)0x6A81); byte[] responseData = null;
        
        // получить возможности смарт-карты
        CardCapabilities cardCapabilities = channel.environment().cardCapabilities(); 

        // при возможности выбора по идентификатору
        if (responseData == null && (cardCapabilities.data(0) & 0x10) != 0)
        {
            // указать идентификатор файла
            byte[] encodedID = new byte[] { (byte)((id >>> 8) & 0xFF), (byte)(id & 0xFF) }; 
                    
            // выбрать каталог по идентификатору
            response = channel.sendCommand(
                INS.SELECT, (byte)0x01, (byte)0x00, encodedID, -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(response)) responseData = response.data;
        }
        // при возможности выбора по пути
        if (responseData == null && (cardCapabilities.data(0) & 0x20) != 0 && path() != null)
        {
            // выделить память для сокращенного пути
            short[] path = path(); byte[] encodedPath = new byte[path.length * 2]; 

            // для всех компонентов пути
            for (int i = 1; i < path.length; i++)
            {
                // закодировать компонент пути
                encodedPath[2 * i - 2] = (byte)((path[i] >>> 8) & 0xFF); 
                encodedPath[2 * i - 1] = (byte) (path[i]        & 0xFF); 
            }
            // закодировать компонент пути
            encodedPath[encodedPath.length - 2] = (byte)((id >>> 8) & 0xFF); 
            encodedPath[encodedPath.length - 1] = (byte) (id        & 0xFF); 
            
            // выбрать каталог по пути
            response = channel.sendCommand(
                INS.SELECT, (byte)0x08, (byte)0x00, encodedPath, -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(response)) responseData = response.data;
        }
        // проверить корректноcть выполнения
        if (responseData == null) ResponseException.check(response); 
        
        // получить описание дочернего каталога
        FileControlInformation info = FileControlInformation.decode(dataCoding(), responseData);
        
        // создать объект каталога
        DedicatedFile dedicatedFile = new DedicatedFile(this, id, info); 
        
        // прочитать дополнительную информацию
        info = info.сombine(dedicatedFile.readInfoExtension(channel)); 
        
        // вернуть объект каталога
        return new DedicatedFile(this, id, info); 
    }
    // выделить файл
    public ElementaryFile selectElementaryFile(
        LogicalChannel channel, short id, FileStructure fileStructure) throws IOException
    {
        // указать начальные условия
        Response response = new Response(new byte[0], (short)0x6A81); byte[] responseData = null; 
        
        // получить возможности смарт-карты
        CardCapabilities cardCapabilities = channel.environment().cardCapabilities(); 

        // при возможности выбора по идентификатору
        if (responseData == null && (cardCapabilities.data(0) & 0x10) != 0)
        {
            // указать идентификатор файла
            byte[] encodedID = new byte[] { (byte)((id >>> 8) & 0xFF), (byte)(id & 0xFF) }; 
                    
            // выбрать файл по идентификатору
            response = channel.sendCommand(
                INS.SELECT, (byte)0x02, (byte)0x00, encodedID, -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(response)) responseData = response.data;
        }
        // при возможности выбора по пути
        if (responseData == null && (cardCapabilities.data(0) & 0x20) != 0 && path() != null)
        {
            // выделить память для сокращенного пути
            short[] path = path(); byte[] encodedPath = new byte[path.length * 2]; 

            // для всех компонентов пути
            for (int i = 1; i < path.length; i++)
            {
                // закодировать компонент пути
                encodedPath[2 * i - 2] = (byte)((path[i] >>> 8) & 0xFF); 
                encodedPath[2 * i - 1] = (byte) (path[i]        & 0xFF); 
            }
            // закодировать компонент пути
            encodedPath[encodedPath.length - 2] = (byte)((id >>> 8) & 0xFF); 
            encodedPath[encodedPath.length - 1] = (byte) (id        & 0xFF); 
            
            // выбрать каталог по пути
            response = channel.sendCommand(
                INS.SELECT, (byte)0x08, (byte)0x00, encodedPath, -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.error(response)) responseData = response.data;
        }
        // проверить отсутствие ошибок
        if (responseData == null) ResponseException.check(response); Byte shortID = null;
        
        // получить описание файла
        FileControlInformation info = FileControlInformation.decode(dataCoding(), responseData);

        // найти сокращенный идентификатор файла
        DataObject[] objs = info.get(Tag.context(0x08, PC.PRIMITIVE));

        // при наличии сокращенного идентификатора
        if (objs.length != 0) { byte[] content = objs[0].content();

            // проверить корректность размера
            if (content.length == 1 && (content[0] & 0x7) == 0)
            {
                // извлечь сокращенный идентификатор
                shortID = (byte)((content[0] >>> 3) & 0x1F); 

                // проверить корректность идентификатора
                if (shortID == 0 || shortID == 31) shortID = null; 
            }
        }
        // при поддержке коротких идентификаторов со стороны карты
        else if ((cardCapabilities.data(0) & 0x04) != 0)
        {
            // найти идентификатор файла
            objs = info.get(Tag.context(0x03, PC.PRIMITIVE)); if (objs.length != 0) 
            {
                // проверить размер объекта
                byte[] content = objs[0].content(); if (content.length == 2)
                { 
                    // извлечь сокращенный идентификатор
                    shortID = (byte)(content[1] & 0x1F); 

                    // проверить корректность идентификатора
                    if (shortID == 0 || shortID == 31) shortID = null; 
                }
            }
        }
        // определить структуру файла
        FileStructure structure = info.fileStructure(); 
            
        // сохранить структуру файла
        if (structure     == FileStructure.UNKNOWN) structure = fileStructure; 
        if (fileStructure == FileStructure.UNKNOWN) fileStructure = structure; 
            
        switch (fileStructure)
        {
        case TRANSPARENT:
        {
            // при несовпадении структуры файла
            if (structure != FileStructure.TRANSPARENT)
            {
                // выбросить исключение
                throw new ResponseException((short)0x6981); 
            }
            // вернуть объект файла
            return new TransparentFile(this, id, shortID, info); 
        }
        case RECORD:
        {
            // при несовпадении структуры файла
            if (structure != FileStructure.LINEAR_FIXED         && 
                structure != FileStructure.LINEAR_FIXED_TLV     && 
                structure != FileStructure.LINEAR_VARIABLE      && 
                structure != FileStructure.LINEAR_VARIABLE_TLV  && 
                structure != FileStructure.CYCLIC_FIXED         && 
                structure != FileStructure.CYCLIC_FIXED_TLV)
            {
                // выбросить исключение
                throw new ResponseException((short)0x6981); 
            }
            // вернуть объект файла
            return new RecordFile(this, id, shortID, info); 
        }
        case LINEAR_FIXED: case LINEAR_FIXED_TLV:
        {
            // при несовпадении структуры файла
            if (structure != FileStructure.LINEAR_FIXED && 
                structure != FileStructure.LINEAR_FIXED_TLV)
            {
                // выбросить исключение
                throw new ResponseException((short)0x6981); 
            }
            // вернуть объект файла
            return new RecordFile(this, id, shortID, info); 
        }
        case LINEAR_VARIABLE: case LINEAR_VARIABLE_TLV:
        {
            // при несовпадении структуры файла
            if (structure != FileStructure.LINEAR_VARIABLE && 
                structure != FileStructure.LINEAR_VARIABLE_TLV)
            {
                // выбросить исключение
                throw new ResponseException((short)0x6981); 
            }
            // вернуть объект файла
            return new RecordFile(this, id, shortID, info); 
        }
        case CYCLIC_FIXED: case CYCLIC_FIXED_TLV:   
        {
            // при несовпадении структуры файла
            if (structure != FileStructure.CYCLIC_FIXED && 
                structure != FileStructure.CYCLIC_FIXED_TLV)
            {
                // выбросить исключение
                throw new ResponseException((short)0x6981); 
            }
            // вернуть объект файла
            return new RecordFile(this, id, shortID, info); 
        }
        case DATA_OBJECT:        
        {
            // при несовпадении структуры файла
            if (structure != FileStructure.DATA_OBJECT_BERTLV &&
                structure != FileStructure.DATA_OBJECT_SIMPLETLV)
            {
                // выбросить исключение
                throw new ResponseException((short)0x6981); 
            }
            // вернуть объект файла
            return new DataObjectFile(this, id, shortID, info); 
        }
        case DATA_OBJECT_BERTLV:        
        {
            // при несовпадении структуры файла
            if (structure != FileStructure.DATA_OBJECT_BERTLV)
            {
                // выбросить исключение
                throw new ResponseException((short)0x6981); 
            }
            // вернуть объект файла
            return new DataObjectFile(this, id, shortID, info); 
        }
        case DATA_OBJECT_SIMPLETLV:     
        {
            // при несовпадении структуры файла
            if (structure != FileStructure.DATA_OBJECT_SIMPLETLV)
            {
                // выбросить исключение
                throw new ResponseException((short)0x6981); 
            }
            // вернуть объект файла
            return new DataObjectFile(this, id, shortID, info); 
        }
        default: 
        {
            // при поддержке записей со стороны карты
            if ((cardCapabilities.data(0) & 0x03) != 0)
            {
                // вернуть объект файла
                return new DataObjectFile(this, id, shortID, info); 
            }
            // вернуть объект файла
            return new TransparentFile(this, id, shortID, info); 
        }}
    }
    // выделить файл
    public ElementaryFile selectElementaryFile(
        LogicalChannel channel, byte shortID, FileStructure fileStructure) throws IOException
    {
        switch (fileStructure)
        {
        // вернуть объект файла
        case TRANSPARENT            : return new TransparentFile(this, shortID); 
        case RECORD                 : return new RecordFile     (this, shortID); 
        case LINEAR_FIXED           : return new RecordFile     (this, shortID); 
        case LINEAR_FIXED_TLV       : return new RecordFile     (this, shortID); 
        case LINEAR_VARIABLE        : return new RecordFile     (this, shortID); 
        case LINEAR_VARIABLE_TLV    : return new RecordFile     (this, shortID); 
        case CYCLIC_FIXED           : return new RecordFile     (this, shortID); 
        case CYCLIC_FIXED_TLV       : return new RecordFile     (this, shortID);   
        case DATA_OBJECT            : return new DataObjectFile (this, shortID);
        case DATA_OBJECT_BERTLV     : return new DataObjectFile (this, shortID);       
        case DATA_OBJECT_SIMPLETLV  : return new DataObjectFile (this, shortID);           
        default: 
        {
            // получить возможности смарт-карты
            CardCapabilities cardCapabilities = channel.environment().cardCapabilities(); 

            // при поддержке записей со стороны карты
            if ((cardCapabilities.data(0) & 0x03) != 0)
            {
                // вернуть объект файла
                return new RecordFile(this, shortID); 
            }
            // вернуть объект файла
            return new TransparentFile(this, shortID); 
        }}
    }
    // категория файла
    @Override public final int fileCategory() 
    {
        // получить дескриптор файла
        DataObject[] objs = info().get(Tag.context(0x02, PC.PRIMITIVE)); 
            
        // проверить наличие дескриптора
        if (objs.length == 0) return FileCategory.DEDICATED; 

        // получить содержимое
        byte[] content = objs[0].content(); 
        
        // проверить размер содержимого
        if (content.length < 1 || (content[0] & 0x80) != 0) 
        {
            // указать значение по умолчанию
            return FileCategory.DEDICATED; 
        }
        // получить возможность разделения
        int shareable = ((content[0] & 0x40) != 0) ? FileCategory.SHAREABLE : 0; 
            
        // вернуть категорию файла
        return FileCategory.DEDICATED | shareable; 
    }
    // описание алгоритмов
    public final MechanismID[] mechanismIDs() throws IOException
    {
        // указать схему кодирования
        TagScheme tagScheme = dataCoding().tagScheme(); 
        
        // создать список объктов
        List<MechanismID> objs = new ArrayList<MechanismID>(); 
        
        // для всех объектов
        for (DataObject obj : info())
        {
            // проверить тип объекта
            if (!obj.tag().equals(Tag.context(0x0C, PC.CONSTRUCTED))) continue; 
            
            // раскодировать объект
            objs.add(new MechanismID(tagScheme, obj.content())); 
        }
        // вернуть список объектов
        return objs.toArray(new MechanismID[objs.size()]); 
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
        // проверить отсутствие ошибок
        ResponseException.check(response); 
        
        // раскодировать объекты
        return dataCoding().decode(response.data, interindustry); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // прочитать файл
    ///////////////////////////////////////////////////////////////////////////
    public Response readFile(LogicalChannel channel, short id, 
        int secureType, SecureClient secureClient) throws IOException
    {
        try {
            // выбрать элементарный файл
            ElementaryFile elementaryFile = selectElementaryFile(channel, id, FileStructure.UNKNOWN); 
        
            // прочитать данные из файла
            return elementaryFile.readContent(channel, secureType, secureClient); 
        }
        // проверить код ошибки
        catch (ResponseException e) { if (e.SW != 0x6A81) return new Response(e.SW); }
         
        // получить возможности карты
        CardCapabilities cardCapabilities = channel.environment().cardCapabilities(); 
        
        // при поддержке записей
        if ((cardCapabilities.data(0) & 0x03) != 0)
        {
            // прочитать файл записей
            try { return readRecordFile(channel, id, secureType, secureClient); }
                
            // обработать возможную ошибку
            catch (ResponseException e) { if (e.SW != 0x6981) return new Response(e.SW); }
        }
        // при поддержке объектов
        if ((cardCapabilities.data(1) & 0x80) != 0)
        {
            // прочитать файл объектов
            try { return readDataObjectFile(channel, id, secureType, secureClient); }
                
            // обработать возможную ошибку
            catch (ResponseException e) { if (e.SW != 0x6981) return new Response(e.SW); }
        }
        // прочитать бинарный файл
        return readBinaryFile(channel, id, secureType, secureClient); 
    }
    // прочитать бинарный файл
    public Response readBinaryFile(LogicalChannel channel, 
        short id, int secureType, SecureClient secureClient) throws IOException
    {
        // указать параметры команды
        byte p1 = (byte)((id >> 8) & 0xFF); byte p2 = (byte)(id & 0xFF);
        
        // закодировать объект смещения
        byte[] encoded = dataCoding().encode(new DataOffset(0)); 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, 
            secureClient, INS.READ_BINARY_BERTLV, p1, p2, encoded, -1
        ); 
        // при отсутствии ошибок
        if (!Response.error(response))
        {
            // раскодировать объекты
            DataObject[] objs = dataCoding().decode(response.data, true); 

            // проверить наличие одного объекта
            if (objs.length != 1) throw new IOException(); 

            // проверить тип содержимого
            if (!objs[0].tag().equals(Tag.DISCRETIONARY_DATA)) throw new IOException();

            // извлечь содержимое
            return new Response(objs[0].content(), response.SW);
        }
        try {
            // выделить файл
            ElementaryFile elementaryFile = selectElementaryFile(
                channel, id, FileStructure.TRANSPARENT
            ); 
            // прочитать бинарный файл
            return elementaryFile.readContent(channel, secureType, secureClient); 
        }
        // обработать возможную ошибку
        catch (ResponseException e) { return new Response(e.SW); }
    }
    // прочитать бинарный файл
    public Response readBinaryFile(LogicalChannel channel, 
        byte shortID, int secureType, SecureClient secureClient) throws IOException
    {
        // закодировать идентификатор файла
        byte p1 = (byte)(0x80 | shortID); byte p2 = 0x00; 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, 
            secureClient, INS.READ_BINARY, p1, p2, new byte[0], -1
        ); 
        // проверить отсутствие ошибок
        if (!Response.error(response)) return response; 
            
        // закодировать объект смещения
        byte[] encoded = dataCoding().encode(new DataOffset(0)); 
        
        // выполнить команду
        Response responseBERTLV = channel.sendCommand(secureType, 
            secureClient, INS.READ_BINARY_BERTLV, (byte)0x00, shortID, encoded, -1
        ); 
        // проверить отсутствие ошибок
        if (Response.error(responseBERTLV)) return response; 
        
        // раскодировать объекты
        DataObject[] objs = dataCoding().decode(responseBERTLV.data, true); 
            
        // проверить наличие одного объекта
        if (objs.length != 1) throw new IOException(); 
            
        // проверить тип содержимого
        if (!objs[0].tag().equals(Tag.DISCRETIONARY_DATA)) throw new IOException();
        
        // извлечь содержимое
        return new Response(objs[0].content(), response.SW);
    }
    // прочитать файл записей
    public Response readRecordFile(LogicalChannel channel, 
        short id, int secureType, SecureClient secureClient) throws IOException
    {
        try {
            // выбрать элементарный файл
            ElementaryFile elementaryFile = selectElementaryFile(
                channel, id, FileStructure.RECORD
            ); 
            // прочитать данные из файла
            return elementaryFile.readContent(channel, secureType, secureClient); 
        }
        // обработать возможную ошибку
        catch (ResponseException e) { return new Response(e.SW); }
    }
    // прочитать файл записей
    public Response readRecordFile(LogicalChannel channel, 
        byte shortID, int secureType, SecureClient secureClient) throws IOException
    {
        // указать параметры команды
        byte p1 = 0x01; byte p2 = (byte)((shortID << 3) | 0x05); 
        
        // выполнить команду
        return channel.sendCommand(secureType, 
            secureClient, INS.READ_RECORDS, p1, p2, new byte[0], -1
        ); 
    }
    // прочитать файл объектов
    public Response readDataObjectFile(LogicalChannel channel, 
        short id, int secureType, SecureClient secureClient) throws IOException
    {
        // указать параметры команды
        byte p1 = (byte)((id >>> 8) & 0xFF); byte p2 = (byte)(id & 0xFF); 
        
        // закодировать список тэгов
        byte[] encoded = dataCoding().encode(new TagList()); 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, 
            secureClient, INS.GET_DATA_BERTLV, p1, p2, encoded, -1
        ); 
        // проверить отсутствие ошибок
        if (!Response.error(response)) 
        {
            // выделить текущий каталог
            selectFromChild(channel); return response;
        } 
        try { 
            // выбрать элементарный файл
            ElementaryFile elementaryFile = selectElementaryFile(
                channel, id, FileStructure.DATA_OBJECT
            ); 
            // прочитать данные из файла
            try { return elementaryFile.readContent(channel, secureType, secureClient); }
            
            // выделить текущий каталог
            finally { selectFromChild(channel); }
        }
        // обработать возможную ошибку
        catch (ResponseException e) { return new Response(e.SW); }
    }
    // прочитать файл объектов 
    public Response readDataObjectFile(LogicalChannel channel, 
        byte shortID, int secureType, SecureClient secureClient) throws IOException
    {
        // закодировать список тэгов
        byte[] encoded = dataCoding().encode(new TagList()); 
        
        // выполнить команду
        Response response = channel.sendCommand(secureType, 
            secureClient, INS.GET_DATA_BERTLV, (byte)0x00, shortID, encoded, -1
        ); 
        // проверить отсутствие ошибок
        if (!Response.error(response)) selectFromChild(channel); 
        
        return response;
    }
}

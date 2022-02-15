using System;
using System.Collections.Generic;
using System.IO;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Каталог файлов
    ///////////////////////////////////////////////////////////////////////////////
    public class DedicatedFile : File
    {
        // выделить каталог по имени
        public static DedicatedFile Select(LogicalChannel channel, byte[] name)
        {
            // указать начальные условия
            Response response = new Response(new byte[0], 0x6A81); 

            // получить возможности смарт-карты
            BER.CardCapabilities cardCapabilities = channel.Environment.CardCapabilities; 

            // проверить возможность выбора по имени
            if ((cardCapabilities.Data(0) & 0x80) == 0) ResponseException.Check(response); 
        
            // список информации файлов
            List<Byte[]> infos = new List<Byte[]>(); 
        
            // выбрать файл по имени
            response = channel.SendCommand(INS.Select, 0x04, 0x00, name, -1); 

            // проверить отсутствие ошибок
            ResponseException.Check(response); infos.Add(response.Data);
        
            // при возможности выбора по идентификатору
            if ((cardCapabilities.Data(0) & 0x10) != 0)
            {
                // для всех родительских каталогов
                while (!Response.Error(response))
                {
                    // выбрать родительский каталог
                    response = channel.SendCommand(INS.Select, 0x03, 0x00, new byte[0], -1); 

                    // добавить информацию в список
                    infos.Add(response.Data);
                }
            }
            // указать способ кодирования
            DataCoding dataCoding = channel.Environment.DataCoding; DedicatedFile dedicatedFile = null;
        
            // для всех родительских каталогов
            for (int i = infos.Count - 1; i > 0; i--)
            {
                // получить описание каталога
                BER.FileControlInformation info = BER.FileControlInformation.Decode(dataCoding, infos[i]); 
            
                // получить имя каталога
                DataObject[] objs = info[Tag.Context(0x04, ASN1.PC.Primitive)]; if (objs.Length != 0)
                {
                    // извлечь имя каталога
                    byte[] fileName = objs[0].Content; 

                    // выбрать файл по имени
                    response = channel.SendCommand(INS.Select, 0x04, 0x0C, fileName, 0); 

                    // проверить отсутствие ошибок
                    if (Response.Error(response)) { dedicatedFile = null; break; } 
        
                    // при отсутствии родительского каталога
                    if (dedicatedFile == null)
                    {
                        // создать объект каталога
                        dedicatedFile = new DedicatedFile(fileName, dataCoding, info); 

                        // прочитать дополнительную информацию
                        info = info.Combine(dedicatedFile.ReadInfoExtension(channel)); 
                    
                        // создать объект каталога
                        dedicatedFile = new DedicatedFile(fileName, dataCoding, info); 
                    }
                    else {
                        // создать объект каталога
                        dedicatedFile = new DedicatedFile(dedicatedFile, fileName, info); 

                        // прочитать дополнительную информацию
                        info = info.Combine(dedicatedFile.ReadInfoExtension(channel)); 

                        // создать объект каталога
                        dedicatedFile = new DedicatedFile(dedicatedFile, fileName, info); 
                    }
                }
                else {
                    // проверить наличие идентификатора
                    ushort? id = info.ID; if (!id.HasValue) { dedicatedFile = null; break; }

                    // указать идентификатор файла
                    byte[] encodedID = new byte[] { (byte)(id >> 8), (byte)(id & 0xFF) }; 
                
                    // выбрать файл по идентификатору
                    response = channel.SendCommand(INS.Select, 0x01, 0x0C, encodedID, 0); 
        
                    // проверить отсутствие ошибок
                    if (Response.Error(response)) { dedicatedFile = null; break; } 
        
                    // при отсутствии родительского каталога
                    if (dedicatedFile == null)
                    {
                        // создать объект каталога
                        dedicatedFile = new DedicatedFile(id.Value, dataCoding, info); 

                        // прочитать дополнительную информацию
                        info = info.Combine(dedicatedFile.ReadInfoExtension(channel)); 
                    
                        // создать объект каталога
                        dedicatedFile = new DedicatedFile(id.Value, dataCoding, info); 
                    }
                    else {
                        // создать объект каталога
                        dedicatedFile = new DedicatedFile(dedicatedFile, id.Value, info); 

                        // прочитать дополнительную информацию
                        info = info.Combine(dedicatedFile.ReadInfoExtension(channel)); 
                    
                        // создать объект каталога
                        dedicatedFile = new DedicatedFile(dedicatedFile, id.Value, info); 
                    }
                }
                // изменить способ кодирования данных
                dataCoding = info.GetDataCoding(dataCoding); 
            }{
                // получить описание каталога
                BER.FileControlInformation info = BER.FileControlInformation.Decode(dataCoding, infos[0]); 
            
                if (infos.Count > 1)
                {
                    // выбрать файл по имени
                    response = channel.SendCommand(INS.Select, 0x04, 0x0C, name, 0);         

                    // проверить отсутствие ошибок
                    ResponseException.Check(response);
                }
                // при отсутствии родительского каталога
                if (dedicatedFile == null) 
                {
                    // создать объект каталога
                    dedicatedFile = new DedicatedFile(name, dataCoding, info);

                    // прочитать дополнительную информацию
                    info = info.Combine(dedicatedFile.ReadInfoExtension(channel)); 

                    // создать объект каталога
                    dedicatedFile = new DedicatedFile(name, dataCoding, info);
                }
                else {
                    // создать объект каталога
                    dedicatedFile = new DedicatedFile(dedicatedFile, name, info); 

                    // прочитать дополнительную информацию
                    info = info.Combine(dedicatedFile.ReadInfoExtension(channel)); 

                    // создать объект каталога
                    dedicatedFile = new DedicatedFile(dedicatedFile, name, info); 
                }
            }
            return dedicatedFile;
        }
        // выделить каталог по пути
        public static DedicatedFile Select(LogicalChannel channel, ushort[] path)
        {
            // проверить наличие пути
            if (path == null || path.Length == 0) throw new ArgumentException(); 
        
            // проверить корневой элемент
            if (path[0] != 0x3F00) throw new ArgumentException(); byte[] responseData = null;

            // получить возможности смарт-карты
            BER.CardCapabilities cardCapabilities = channel.Environment.CardCapabilities; 

            // выбрать мастер-файл
            Response response = channel.SendCommand(INS.Select, 0x00, 0x00, new byte[0], -1); 

            // проверить отсутствие ошибок
            if (!Response.Error(response)) responseData = response.Data;
        
            // при возможности выбора по идентификатору
            if (responseData != null && (cardCapabilities.Data(0) & 0x10) != 0)
            {
                // выбрать мастер-файл
                response = channel.SendCommand(INS.Select, 0x00, 0x00, new byte[] { 0x3F, 0x00 }, -1); 

                // проверить отсутствие ошибок
                if (!Response.Error(response)) responseData = response.Data;
            }
            // при возможности выбора по пути
            if (responseData != null && (cardCapabilities.Data(0) & 0x20) != 0)
            {
                // выбрать мастер-файл
                response = channel.SendCommand(INS.Select, 0x08, 0x00, new byte[0], -1); 

                // проверить отсутствие ошибок
                if (!Response.Error(response)) responseData = response.Data;
            }
            // при ошибке выбросить исключение
            if (responseData == null) ResponseException.Check(response); 
        
            // указать способ кодирования
            DataCoding dataCoding = channel.Environment.DataCoding; 
        
            // получить описание каталога
            BER.FileControlInformation info = BER.FileControlInformation.Decode(dataCoding, responseData); 
        
            // создать объект мастер-файла
            DedicatedFile dedicatedFile = new DedicatedFile(path[0], dataCoding, info); 
        
            // прочитать дополнительную информацию
            info = info.Combine(dedicatedFile.ReadInfoExtension(channel)); 
        
            // создать объект мастер файла
            dedicatedFile = new DedicatedFile(path[0], dataCoding, info); 
        
            // для всех внутренних каталогов
            for (int i = 1; i < path.Length; i++)
            {
                // выбрать внутренний каталог
                dedicatedFile = dedicatedFile.SelectDedicatedFile(channel, path[i]); 
            }
            return dedicatedFile; 
        }
        // конструктор
        private DedicatedFile(ushort id, DataCoding dataCoding, BER.FileControlInformation info) 
        
            // сохранить переданные параметры
            : base(id, dataCoding, info) 
        { 
            // получить имя каталога
            DataObject[] objs = info[Tag.Context(0x04, ASN1.PC.Primitive)]; 
            
            // сохранить имя каталога
            name = (objs.Length != 0) ? objs[0].Content : null; 
        }
        // конструктор
        private DedicatedFile(byte[] name, DataCoding dataCoding, BER.FileControlInformation info) 
        
            // сохранить переданные параметры
            : base(info.ID, dataCoding, info) { this.name = name; }

        // конструктор
        private DedicatedFile(DedicatedFile parent, ushort id, BER.FileControlInformation info) 
        
            // сохранить переданные параметры
            : base(parent, id, info) 
        { 
            // получить имя каталога
            DataObject[] objs = info[Tag.Context(0x04, ASN1.PC.Primitive)]; 
            
            // сохранить имя каталога
            name = (objs.Length != 0) ? objs[0].Content : null; 
        }
        // конструктор
        private DedicatedFile(DedicatedFile parent, byte[] name, BER.FileControlInformation info) 
        
            // сохранить переданные параметры
            : base(parent, info.ID, info) { this.name = name; }

        // имя каталога
        public byte[] Name { get { return name; }} private byte[] name;
    
        // выделить текущий каталог при выделенном дочернем файле
        internal void SelectFromChild(LogicalChannel channel)
        {
            // при наличии идентификатора
            if (ID.HasValue && Parent == null)
            {
                // выбрать каталог по идентификатору
                DedicatedFile.Select(channel, new ushort[] { ID.Value } ); 
            }
            // при наличии идентификатора
            else if (ID.HasValue && Parent != null)
            {
                // выбрать каталог по идентификатору
                Parent.SelectDedicatedFile(channel, ID.Value); 
            }
            else {
                // выбрать каталог по имени
                Response response = channel.SendCommand(INS.Select, 0x04, 0x0C, name, 0); 

                // проверить отсутствие ошибок
                ResponseException.Check(response);
            }
        }
        // прочитать дополнительную информацию
        private DataObjectTemplate ReadInfoExtension(LogicalChannel channel)
        {
            // получить идентификатор файла с дополнительной информацией
            DataObject[] objs = Info[Tag.Context(0x07, ASN1.PC.Primitive)]; 
        
            // проверить наличие файла
            if (objs.Length == 0) return null; byte[] content = objs[0].Content;
        
            // проверить размер идентификатора
            if (content.Length != 2) return null; 
        
            // раскодировать идентификатор файла
            ushort fileID = (ushort)((content[0] << 8) | content[1]); 

            // прочитать файл объектов
            Response response = ReadDataFile(channel, fileID, SecureType.None, null); 
        
            // проверить отсутствие ошибок
            ResponseException.Check(response); 
                
            // для всех объектов
            foreach (DataObject obj in DataCoding.Decode(response.Data, true))
            {
                // проверить тип объекта
                if (obj.Tag == Tag.FileControlInformation)
                {
                    // выполнить преобразование типа
                    return new BER.FileControlInformation(DataCoding.TagScheme, obj.Content); 
                }
                // проверить тип объекта
                if (obj.Tag == Tag.FileControlParameters)
                {
                    // выполнить преобразование типа
                    return new BER.FileControlParameters(DataCoding.TagScheme, obj.Content); 
                }
            }
            return null; 
        }
        // выделить родительский каталог
        public override DedicatedFile SelectParent(LogicalChannel channel)
        {
            // проверить наличие родительского каталога
            if (Parent == null) return null; DataCoding parentCoding = channel.Environment.DataCoding; 
        
            // указать способ кодирования
            if (Parent.Parent != null) parentCoding = Parent.Parent.DataCoding; 

            // указать начальные условия
            Response response = new Response(new byte[0], 0x6A81); byte[] responseData = null; 
        
            // получить возможности смарт-карты
            BER.CardCapabilities cardCapabilities = channel.Environment.CardCapabilities; 

            // при возможности выбора по идентификатору
            if (responseData == null && (cardCapabilities.Data(0) & 0x10) != 0)
            {
                // выбрать родительский каталог
                response = channel.SendCommand(INS.Select, 0x03, 0x00, new byte[0], -1); 

                // проверить отсутствие ошибок
                if (!Response.Error(response)) responseData = response.Data; 
            }
            // при возможности выбора по пути
            if (responseData == null && (cardCapabilities.Data(0) & 0x20) != 0 && Parent.Path != null)
            {
                // выделить память для сокращенного пути
                ushort[] path = Parent.Path; byte[] encodedPath = new byte[(path.Length - 1) * 2]; 

                // для всех компонентов пути
                for (int i = 1; i < path.Length; i++)
                {
                    // закодировать компонент пути
                    encodedPath[2 * i - 2] = (byte)(path[i] >>   8); 
                    encodedPath[2 * i - 1] = (byte)(path[i] & 0xFF); 
                }
                // выбрать каталог по пути
                response = channel.SendCommand(INS.Select, 0x08, 0x00, encodedPath, -1); 

                // проверить отсутствие ошибок
                if (!Response.Error(response)) responseData = response.Data; 
            }
            // при возможности выбора по имени
            if (responseData == null && (cardCapabilities.Data(0) & 0x80) != 0 && Parent.Name != null)
            {
                // выбрать каталог по имени
                response = channel.SendCommand(INS.Select, 0x04, 0x00, Parent.Name, -1); 

                // проверить отсутствие ошибок
                if (!Response.Error(response)) responseData = response.Data; 
            }
            // проверить отсутствие ошибок
            if (responseData == null) ResponseException.Check(response);
        
            // получить описание каталога
            BER.FileControlInformation info = BER.FileControlInformation.Decode(parentCoding, response.Data); 
        
            // прочитать дополнительную информацию
            info = info.Combine(Parent.ReadInfoExtension(channel)); if (Parent.ID.HasValue)
            {
                // вернуть объект родительского каталога
                return new DedicatedFile(Parent.Parent, Parent.ID.Value, info); 
            }
            else {
                // вернуть объект родительского каталога
                return new DedicatedFile(Parent.Parent, Parent.Name, info); 
            }
        }
        // выделить каталог или файл
        public File SelectFile(LogicalChannel channel, 
            BER.FileReference reference, FileStructure fileStructure)
        {
            // для мастер-файла
            if (reference.Content.Length == 0) 
            {
                // выделить мастер-файл
                return DedicatedFile.Select(channel, reference.Path);
            } 
            // при указании сокращенного идентификатора
            if (reference.Content.Length == 1)
            {
                // выделить элементарный файл
                return SelectElementaryFile(channel, reference.ShortID.Value, fileStructure); 
            }
            // при указании идентификатора
            if (reference.Content.Length == 2) { ushort id = reference.ID.Value; 
            
                // вернуть мастер-файл
                if (id == 0x3F00) return DedicatedFile.Select(channel, reference.Path); 
            
                // вернуть текущимй файл
                if (id == 0x3FFF) return this; 
            
                // выделить файл
                try { return SelectElementaryFile(channel, id, fileStructure); }

                // выделить каталог
                catch { return SelectDedicatedFile(channel, id); }
            }
            // указать начальные условия
            ushort[] path = reference.Path; int type = -1;
        
            // при указании только пути
            if ((reference.Content.Length % 2) == 0) 
            { 
                // при указании идентификатора каталога
                if (path[0] != 0x3F00 && path[0] != 0x3FFF) {  path[0] = 0x3FFF;
                
                    // проверить совпадение идентификатора
                    if (!ID.HasValue || path[0] != ID.Value) throw new InvalidOperationException(); 
                }
            }
            // для абсолютного пути
            else if (reference.P1.Value == 0x08) 
            {
                // изменить размер буфера
                Array.Resize(ref path, path.Length + 1); 
            
                // сместить путь 
                Array.Copy(path, 0, path, 1, path.Length - 1); path[0] = 0x3F00;
            }
            // для относительного пути
            else if (reference.P1.Value == 0x09)
            {
                // изменить размер буфера
                Array.Resize(ref path, path.Length + 1); 
            
                // сместить путь 
                Array.Copy(path, 0, path, 1, path.Length - 1); path[0] = 0x3FFF;
            }
            // для относительного пути каталога
            else if (reference.P1.Value == 0x01)
            {
                // изменить размер буфера
                Array.Resize(ref path, path.Length + 1); type = 0; 
            
                // сместить путь 
                Array.Copy(path, 0, path, 1, path.Length - 1); path[0] = 0x3FFF;
            }
            // для относительного пути файла
            else if (reference.P1.Value == 0x02)
            {
                // проверить отсутствие ошибок
                if (reference.Content.Length != 3) throw new InvalidOperationException(); 
            
                // изменить размер буфера
                Array.Resize(ref path, path.Length + 1); type = 0; 
            
                // сместить путь 
                Array.Copy(path, 0, path, 1, path.Length - 1); path[0] = 0x3FFF;
            }
            // обработать возможную ошибку
            else throw new NotSupportedException(); 
        
            // указать начальные условия 
            DedicatedFile dedicatedFile = this; int i = 1; 
        
            // для абсолютного пути
            if (path[0] == 0x3F00)
            {
                // список родительских каталогов
                List<DedicatedFile> dedicatedFiles = new List<DedicatedFile>(); 
                
                // для всех родительских каталогов
                for (; dedicatedFile != null; dedicatedFile = dedicatedFile.Parent)
                {
                    // сохранить родительский каталог
                    dedicatedFiles.Add(dedicatedFile); 
                }
                // для всех компонентов пути
                for (i = 0, dedicatedFile = null; i < path.Length; i++)
                {
                    // проверить наличие каталога
                    if (dedicatedFiles.Count <= i) break; 
                    
                    // получить каталог
                    DedicatedFile nextFile = dedicatedFiles[dedicatedFiles.Count - 1 - i]; 

                    // определить идентификатор файла
                    ushort? id = nextFile.ID; if (!id.HasValue) break; 
                    
                    // проверить совпадение идентификаторов
                    if (path[i] != id.Value) break; dedicatedFile = nextFile; 
                }
                // выбрать каталог по абсолютному пути
                if (dedicatedFile == null) return DedicatedFile.Select(channel, path);
                
                // для всех родительских каталогов
                for (DedicatedFile parent = this; parent != dedicatedFile; )
                {
                    // выделить родительский каталог
                    parent = parent.SelectParent(channel); 
                }
                // проверить достижение файла
                if (i == path.Length) return dedicatedFile; 
            }
            // для всех каталогов
            for (; i < path.Length - 1; i++)
            {
                // выбрать внутренний каталог
                dedicatedFile = dedicatedFile.SelectDedicatedFile(channel, path[i]); 
            }
            // выделить каталог или файл
            if (type == 0) return dedicatedFile.SelectDedicatedFile (channel, path[path.Length - 1]); 
            if (type == 1) return dedicatedFile.SelectElementaryFile(channel, path[path.Length - 1], fileStructure); 
            
            // выделить файл
            try { return dedicatedFile.SelectElementaryFile(channel, path[path.Length - 1], fileStructure); }

            // выделить каталог
            catch { return dedicatedFile.SelectDedicatedFile(channel, path[path.Length - 1]); }
        }
        // выделить дочерний каталог
        public DedicatedFile SelectDedicatedFile(LogicalChannel channel, ushort id)
        {
            // указать начальные условия
            Response response = new Response(new byte[0], 0x6A81); byte[] responseData = null; 
        
            // получить возможности смарт-карты
            BER.CardCapabilities cardCapabilities = channel.Environment.CardCapabilities; 

            // при возможности выбора по идентификатору
            if (responseData == null && (cardCapabilities.Data(0) & 0x10) != 0)
            {
                // указать идентификатор файла
                byte[] encodedID = new byte[] { (byte)(id >> 8), (byte)(id & 0xFF) }; 
                    
                // выбрать каталог по идентификатору
                response = channel.SendCommand(INS.Select, 0x01, 0x00, encodedID, -1); 

                // проверить отсутствие ошибок
                if (!Response.Error(response)) responseData = response.Data;
            }
            // при возможности выбора по пути
            if (responseData == null && (cardCapabilities.Data(0) & 0x20) != 0 && Path != null)
            {
                // выделить память для сокращенного пути
                ushort[] path = Path; byte[] encodedPath = new byte[path.Length * 2]; 

                // для всех компонентов пути
                for (int i = 1; i < path.Length; i++)
                {
                    // закодировать компонент пути
                    encodedPath[2 * i - 2] = (byte)(path[i] >>   8); 
                    encodedPath[2 * i - 1] = (byte)(path[i] & 0xFF); 
                }
                // закодировать компонент пути
                encodedPath[encodedPath.Length - 2] = (byte)(id >>   8); 
                encodedPath[encodedPath.Length - 1] = (byte)(id & 0xFF); 
            
                // выбрать каталог по пути
                response = channel.SendCommand(INS.Select, 0x08, 0x00, encodedPath, -1); 

                // проверить отсутствие ошибок
                if (!Response.Error(response)) responseData = response.Data;
            }
            // проверить корректноcть выполнения
            if (responseData == null) ResponseException.Check(response); 
        
            // получить описание дочернего каталога
            BER.FileControlInformation info = BER.FileControlInformation.Decode(DataCoding, responseData);

            // создать объект каталога
            DedicatedFile dedicatedFile = new DedicatedFile(this, id, info); 
        
            // прочитать дополнительную информацию
            info = info.Combine(dedicatedFile.ReadInfoExtension(channel)); 
        
            // вернуть объект каталога
            return new DedicatedFile(this, id, info); 
        }
        // выделить файл
        public ElementaryFile SelectElementaryFile(
            LogicalChannel channel, ushort id, FileStructure fileStructure)
        {
            // указать начальные условия
            Response response = new Response(new byte[0], 0x6A81); byte[] responseData = null; 
        
            // получить возможности смарт-карты
            BER.CardCapabilities cardCapabilities = channel.Environment.CardCapabilities; 

            // при возможности выбора по идентификатору
            if (responseData == null && (cardCapabilities.Data(0) & 0x10) != 0)
            {
                // указать идентификатор файла
                byte[] encodedID = new byte[] { (byte)(id >> 8), (byte)(id & 0xFF) }; 
                    
                // выбрать файл по идентификатору
                response = channel.SendCommand(INS.Select, 0x02, 0x00, encodedID, -1); 

                // проверить отсутствие ошибок
                if (!Response.Error(response)) responseData = response.Data;
            }
            // при возможности выбора по пути
            if (responseData == null && (cardCapabilities.Data(0) & 0x20) != 0 && Path != null)
            {
                // выделить память для сокращенного пути
                ushort[] path = Path; byte[] encodedPath = new byte[path.Length * 2]; 

                // для всех компонентов пути
                for (int i = 1; i < path.Length; i++)
                {
                    // закодировать компонент пути
                    encodedPath[2 * i - 2] = (byte)(path[i] >>   8); 
                    encodedPath[2 * i - 1] = (byte)(path[i] & 0xFF); 
                }
                // закодировать компонент пути
                encodedPath[encodedPath.Length - 2] = (byte)(id >>   8); 
                encodedPath[encodedPath.Length - 1] = (byte)(id & 0xFF); 
            
                // выбрать каталог по пути
                response = channel.SendCommand(INS.Select, 0x08, 0x00, encodedPath, -1); 

                // проверить отсутствие ошибок
                if (!Response.Error(response)) responseData = response.Data;
            }
            // при успешном выделении файла
            if (responseData == null) ResponseException.Check(response); byte? shortID = null; 

            // получить описание файла
            BER.FileControlInformation info = BER.FileControlInformation.Decode(DataCoding, responseData);

            // найти сокращенный идентификатор файла
            DataObject[] objs = info[Tag.Context(0x08, ASN1.PC.Primitive)];

            // при наличии сокращенного идентификатора
            if (objs.Length != 0) { byte[] content = objs[0].Content;

                // проверить корректность размера
                if (content.Length == 1 && (content[0] & 0x7) == 0)
                {
                    // извлечь сокращенный идентификатор
                    shortID = (byte)((content[0] >> 3) & 0x1F); 
                
                    // проверить корректность идентификатора
                    if (shortID == 0 || shortID == 31) shortID = null; 
                }
            }
            // при поддержке коротких идентификаторов со стороны карты
            else if ((cardCapabilities.Data(0) & 0x04) != 0)
            {
                // найти идентификатор файла
                objs = info[Tag.Context(0x03, ASN1.PC.Primitive)]; if (objs.Length != 0) 
                {
                    // проверить размер объекта
                    byte[] content = objs[0].Content; if (content.Length == 2)
                    { 
                        // извлечь сокращенный идентификатор
                        shortID = (byte)(content[1] & 0x1F); 

                        // проверить корректность идентификатора
                        if (shortID == 0 || shortID == 31) shortID = null; 
                    }
                }
            }
            // определить структуру файла
            FileStructure structure = info.FileStructure; 
            
            // сохранить структуру файла
            if (structure     == FileStructure.Unknown) structure = fileStructure; 
            if (fileStructure == FileStructure.Unknown) fileStructure = structure; 
            
            switch (fileStructure)
            {
            case FileStructure.Transparent:
            {
                // при несовпадении структуры файла
                if (structure != FileStructure.Transparent)
                {
                    // выбросить исключение
                    throw new ResponseException(0x6981); 
                }
                // вернуть объект файла
                return new TransparentFile(this, id, shortID, info); 
            }
            case FileStructure.Record:
            {
                // при несовпадении структуры файла
                if (structure != FileStructure.Record               && 
                    structure != FileStructure.LinearFixed          && 
                    structure != FileStructure.LinearFixedTLV       && 
                    structure != FileStructure.LinearVariable       && 
                    structure != FileStructure.LinearVariableTLV    && 
                    structure != FileStructure.CyclicFixed          && 
                    structure != FileStructure.CyclicFixedTLV)
                {
                    // выбросить исключение
                    throw new ResponseException(0x6981); 
                }
                // вернуть объект файла
                return new RecordFile(this, id, shortID, info); 
            }
            case FileStructure.LinearFixed: case FileStructure.LinearFixedTLV:
            {
                // при несовпадении структуры файла
                if (structure != FileStructure.LinearFixed && 
                    structure != FileStructure.LinearFixedTLV)
                {
                    // выбросить исключение
                    throw new ResponseException(0x6981); 
                }
                // вернуть объект файла
                return new RecordFile(this, id, shortID, info); 
            }
            case FileStructure.LinearVariable: case FileStructure.LinearVariableTLV:
            {
                // при несовпадении структуры файла
                if (structure != FileStructure.LinearVariable && 
                    structure != FileStructure.LinearVariableTLV)
                {
                    // выбросить исключение
                    throw new ResponseException(0x6981); 
                }
                // вернуть объект файла
                return new RecordFile(this, id, shortID, info); 
            }
            case FileStructure.CyclicFixed: case FileStructure.CyclicFixedTLV:   
            {
                // при несовпадении структуры файла
                if (structure != FileStructure.CyclicFixed && 
                    structure != FileStructure.CyclicFixedTLV)
                {
                    // выбросить исключение
                    throw new ResponseException(0x6981); 
                }
                // вернуть объект файла
                return new RecordFile(this, id, shortID, info); 
            }
            case FileStructure.DataObject:
            {
                // при несовпадении структуры файла
                if (structure != FileStructure.DataObjectBERTLV && 
                    structure != FileStructure.DataObjectSimpleTLV)
                {
                    // выбросить исключение
                    throw new ResponseException(0x6981); 
                }
                // вернуть объект файла
                return new DataObjectFile(this, id, shortID, info); 
            }
            case FileStructure.DataObjectBERTLV:        
            {
                // при несовпадении структуры файла
                if (structure != FileStructure.DataObjectBERTLV)
                {
                    // выбросить исключение
                    throw new ResponseException(0x6981); 
                }
                // вернуть объект файла
                return new DataObjectFile(this, id, shortID, info); 
            }
            case FileStructure.DataObjectSimpleTLV:     
            {
                // при несовпадении структуры файла
                if (structure != FileStructure.DataObjectSimpleTLV)
                {
                    // выбросить исключение
                    throw new ResponseException(0x6981); 
                }
                // вернуть объект файла
                return new DataObjectFile(this, id, shortID, info); 
            }
            default:
            {
                // при поддержке записей со стороны карты
                if ((cardCapabilities.Data(0) & 0x03) != 0)
                {
                    // вернуть объект файла
                    return new DataObjectFile(this, id, shortID, info); 
                }
                // вернуть объект файла
                return new TransparentFile(this, id, shortID, info); 
            }}
        }
        // выделить файл
        public ElementaryFile SelectElementaryFile(
            LogicalChannel channel, byte shortID, FileStructure fileStructure) 
        {
            switch (fileStructure)
            {
            // вернуть объект файла
            case ISO7816.FileStructure.Transparent         : return new TransparentFile(this, shortID); 
            case ISO7816.FileStructure.Record              : return new RecordFile     (this, shortID); 
            case ISO7816.FileStructure.LinearFixed         : return new RecordFile     (this, shortID); 
            case ISO7816.FileStructure.LinearFixedTLV      : return new RecordFile     (this, shortID); 
            case ISO7816.FileStructure.LinearVariable      : return new RecordFile     (this, shortID); 
            case ISO7816.FileStructure.LinearVariableTLV   : return new RecordFile     (this, shortID); 
            case ISO7816.FileStructure.CyclicFixed         : return new RecordFile     (this, shortID); 
            case ISO7816.FileStructure.CyclicFixedTLV      : return new RecordFile     (this, shortID);   
            case ISO7816.FileStructure.DataObject          : return new DataObjectFile (this, shortID);
            case ISO7816.FileStructure.DataObjectBERTLV    : return new DataObjectFile (this, shortID);       
            case ISO7816.FileStructure.DataObjectSimpleTLV : return new DataObjectFile (this, shortID);           
            default: 
            {
                // получить возможности смарт-карты
                BER.CardCapabilities cardCapabilities = channel.Environment.CardCapabilities; 

                // при поддержке записей со стороны карты
                if ((cardCapabilities.Data(0) & 0x03) != 0)
                {
                    // вернуть объект файла
                    return new RecordFile(this, shortID); 
                }
                // вернуть объект файла
                return new TransparentFile(this, shortID); 
            }}
        }
        // категория файла
        public override int FileCategory { get  
        {
            // получить дескриптор файла
            DataObject[] objs = Info[Tag.Context(0x02, ASN1.PC.Primitive)]; 
            
            // проверить наличие дескриптора
            if (objs.Length == 0) return ISO7816.FileCategory.Dedicated; 

            // получить содержимое
            byte[] content = objs[0].Content; 
            
            // проверить размер содержимого
            if (content.Length < 1 || (content[0] & 0x80) != 0) 
            {
                // указать значение по умолчанию
                return ISO7816.FileCategory.Dedicated; 
            }
            // получить возможность разделения
            int shareable = ((content[0] & 0x40) != 0) ? ISO7816.FileCategory.Shareable : 0; 
            
            // вернуть категорию файла
            return ISO7816.FileCategory.Dedicated | shareable; 
        }}
        // описание алгоритмов
        public BER.MechanismID[] MechanismIDs { get 
        {
            // указать схему кодирования
            TagScheme tagScheme = DataCoding.TagScheme; 
        
            // создать список объктов
            List<BER.MechanismID> objs = new List<BER.MechanismID>(); 
        
            // для всех объектов
            foreach (DataObject obj in Info)
            {
                // проверить тип объекта
                if (obj.Tag != Tag.Context(0x0C, ASN1.PC.Constructed)) continue; 
            
                // раскодировать объект
                objs.Add(new BER.MechanismID(tagScheme, obj.Content)); 
            }
            // вернуть список объектов
            return objs.ToArray(); 
        }}
        ///////////////////////////////////////////////////////////////////////////
        // прочитать объекты
        ///////////////////////////////////////////////////////////////////////////
        public SimpleTLV ReadObject(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, int tag)
        {
            // проверить корректноть тэга
            if (tag < 0 || tag > 255) throw new ArgumentException(); 

            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.GetData, 0x02, (byte)tag, new byte[0], -1
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        
            // проверить наличие данных
            if (response.Data.Length == 0) return null; 

            // раскодировать объект
            return SimpleTLV.Decode(response.Data)[0]; 
        }
        // прочитать объект
        public DataObject ReadObject(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, Tag tag, bool interindustry) 
        {
            // закодировать тэг
            byte[] encoded = tag.Encoded; if (encoded.Length == 1)
            {
                // выполнить команду
                Response response = channel.SendCommand(secureType, 
                    secureClient, INS.GetData, 0x00, encoded[0], new byte[0], -1
                ); 
                // проверить отсутствие ошибок
                if (!Response.Error(response))
                {
                    // проверить наличие данных
                    if (response.Data.Length == 0) return null; 

                    // раскодировать объект
                    return DataCoding.Decode(encoded, interindustry)[0]; 
                }
            }
            else if (encoded.Length == 2)
            {
                // выполнить команду
                Response response = channel.SendCommand(secureType, 
                    secureClient, INS.GetData, encoded[0], encoded[1], new byte[0], -1
                ); 
                // проверить отсутствие ошибок
                if (!Response.Error(response))
                {
                    // проверить наличие данных
                    if (response.Data.Length == 0) return null; 

                    // раскодировать объект
                    return DataCoding.Decode(encoded, interindustry)[0]; 
                }
            }
            // прочитать объекты
            return ReadObjects(channel, secureType, 
                secureClient, new Tag[] { tag }, interindustry)[0];
        }
        // прочитать объекты
        public DataObject[] ReadObjects(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, Tag[] tags, bool interindustry) 
        {
            // закодировать список тэгов
            byte[] encoded = DataCoding.Encode(new BER.TagList(tags)); 

            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.GetDataBERTLV, 0x00, 0x00, encoded, -1
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response); 
            
            // раскодировать объекты
            return DataCoding.Decode(response.Data, interindustry); 
        }
        // прочитать объекты
        public DataObject[] ReadObjects(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, Header[] headers, bool interindustry)
        {
            // закодировать список заголовков
            byte[] encoded = DataCoding.Encode(new BER.HeaderList(headers)); 

            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.GetDataBERTLV, 0x00, 0x00, encoded, -1
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response); 
            
            // раскодировать объекты
            return DataCoding.Decode(response.Data, interindustry); 
        }
        // прочитать объекты
        public DataObject[] ReadObjects(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, 
            ExtendedHeader[] extendedHeaders, bool interindustry)
        {
            // закодировать список заголовков
            byte[] encoded = DataCoding.Encode(new BER.ExtendedHeaderList(extendedHeaders)); 

            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.GetDataBERTLV, 0x00, 0x00, encoded, -1
            ); 
            // проверить отсутствие ошибок
            ResponseException.Check(response); 
            
            // раскодировать объекты
            return DataCoding.Decode(response.Data, interindustry); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // прочитать файл
        ///////////////////////////////////////////////////////////////////////////
        public Response ReadFile(LogicalChannel channel, 
            ushort id, SecureType secureType, SecureClient secureClient)
        {
            try {
                // выбрать элементарный файл
                ElementaryFile elementaryFile = SelectElementaryFile(
                    channel, id, FileStructure.Unknown
                ); 
                // прочитать данные из файла
                return elementaryFile.ReadContent(channel, secureType, secureClient); 
            }
            // проверить код ошибки
            catch (ResponseException e) { if (e.SW != 0x6A81) return new Response(e.SW); }
        
            // получить возможности карты
            BER.CardCapabilities cardCapabilities = channel.Environment.CardCapabilities; 
        
            // при поддержке записей
            if ((cardCapabilities.Data(0) & 0x03) != 0)
            {
                // прочитать файл записей
                try { return ReadRecordFile(channel, id, secureType, secureClient); }
                
                // обработать возможную ошибку
                catch (ResponseException e) { if (e.SW != 0x6981) return new Response(e.SW); }
            }
            // при поддержке объектов
            if ((cardCapabilities.Data(1) & 0x80) != 0)
            {
                // прочитать файл объектов
                try { return ReadDataFile(channel, id, secureType, secureClient); }
                
                // обработать возможную ошибку
                catch (ResponseException e) { if (e.SW != 0x6981) return new Response(e.SW); }
            }
            // прочитать бинарный файл
            return ReadBinaryFile(channel, id, secureType, secureClient); 
        }
        // прочитать бинарный файл
        public Response ReadBinaryFile(LogicalChannel channel, 
            ushort id, SecureType secureType, SecureClient secureClient)
        {
            // указать параметры команды
            byte p1 = (byte)(id >> 8); byte p2 = (byte)(id & 0xFF);
        
            // закодировать объект смещения
            byte[] encoded = DataCoding.Encode(new BER.DataOffset(0)); 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ReadBinaryBERTLV, p1, p2, encoded, -1
            ); 
            // при отсутствии ошибок
            if (!Response.Error(response))
            {
                // раскодировать объекты
                DataObject[] objs = DataCoding.Decode(response.Data, true); 

                // проверить наличие одного объекта
                if (objs.Length != 1) throw new InvalidDataException(); 

                // проверить тип содержимого
                if (objs[0].Tag != Tag.DiscretionaryData) throw new InvalidDataException();

                // извлечь содержимое
                return new Response(objs[0].Content, response.SW);
            }
            try {
                // выделить файл
                ElementaryFile elementaryFile = SelectElementaryFile(
                    channel, id, FileStructure.Transparent
                ); 
                // прочитать бинарный файл
                return elementaryFile.ReadContent(channel, secureType, secureClient); 
            }
            // обработать возможную ошибку
            catch (ResponseException e) { return new Response(e.SW); }
        }
        // прочитать бинарный файл
        public Response ReadBinaryFile(LogicalChannel channel, 
            byte shortID, SecureType secureType, SecureClient secureClient) 
        {
            // закодировать идентификатор файла
            byte p1 = (byte)(0x80 | (shortID & 0x1F)); byte p2 = 0x00; 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ReadBinary, p1, p2, new byte[0], -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.Error(response)) return response; 
            
            // закодировать объект смещения
            byte[] encoded = DataCoding.Encode(new BER.DataOffset(0)); 
        
            // выполнить команду
            Response responseBERTLV = channel.SendCommand(secureType, 
                secureClient, INS.ReadBinaryBERTLV, 0x00, (byte)shortID, encoded, -1
            ); 
            // проверить отсутствие ошибок
            if (Response.Error(responseBERTLV)) return response; 
        
            // раскодировать объекты
            DataObject[] objs = DataCoding.Decode(responseBERTLV.Data, true); 
            
            // проверить наличие одного объекта
            if (objs.Length != 1) throw new InvalidDataException(); 

            // проверить тип содержимого
            if (objs[0].Tag != Tag.DiscretionaryData) throw new InvalidDataException();
        
            // извлечь содержимое
            return new Response(objs[0].Content, response.SW);
        }
        // прочитать файл записей
        public Response ReadRecordFile(LogicalChannel channel, 
            ushort id, SecureType secureType, SecureClient secureClient)
        {
            try {
                // выбрать элементарный файл
                ElementaryFile elementaryFile = SelectElementaryFile(
                    channel, id, FileStructure.Record
                ); 
                // прочитать данные из файла
                return elementaryFile.ReadContent(channel, secureType, secureClient); 
            }
            // обработать возможную ошибку
            catch (ResponseException e) { return new Response(e.SW); }
        }
        // прочитать файл записей
        public Response ReadRecordFile(LogicalChannel channel, 
            byte shortID, SecureType secureType, SecureClient secureClient)
        {
            // указать параметры команды
            byte p1 = 0x01; byte p2 = (byte)((shortID << 3) | 0x05); 
        
            // выполнить команду
            return channel.SendCommand(secureType, 
                secureClient, INS.ReadRecords, p1, p2, new byte[0], -1
            ); 
        }
        // прочитать файл объектов
        public Response ReadDataFile(LogicalChannel channel, 
            ushort id, SecureType secureType, SecureClient secureClient)
        {
            // указать параметры команды
            byte p1 = (byte)(id >> 8); byte p2 = (byte)(id & 0xFF); 
        
            // закодировать список тэгов
            byte[] encoded = DataCoding.Encode(new BER.TagList()); 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.GetDataBERTLV, p1, p2, encoded, -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.Error(response)) 
            {
                // выделить текущий каталог
                SelectFromChild(channel); return response; 
            }
            try { 
                // выбрать элементарный файл
                ElementaryFile elementaryFile = SelectElementaryFile(
                    channel, id, FileStructure.DataObject
                ); 
                // прочитать данные из файла
                try { return elementaryFile.ReadContent(channel, secureType, secureClient); }

                // выделить текущий каталог
                finally { SelectFromChild(channel); }
            }
            // обработать возможную ошибку
            catch (ResponseException e) { return new Response(e.SW); }
        }
        // прочитать файл объектов
        public Response ReadDataFile(LogicalChannel channel, 
            byte shortID, SecureType secureType, SecureClient secureClient)
        {
            // закодировать список тэгов
            byte[] encoded = DataCoding.Encode(new BER.TagList()); 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.GetDataBERTLV, 0x00, (byte)shortID, encoded, -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.Error(response)) SelectFromChild(channel); return response;
        }
    }
}

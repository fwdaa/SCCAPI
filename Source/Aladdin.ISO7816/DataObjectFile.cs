using System;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Элементарный файл объектов
    ///////////////////////////////////////////////////////////////////////////////
    public class DataObjectFile : ElementaryFile
    {
        // конструктор
        internal DataObjectFile(DedicatedFile parent, ushort id) : base(parent, id) {}

        // конструктор
        internal DataObjectFile(DedicatedFile parent, byte shortID) : base(parent, shortID) {}

        // конструктор
        internal DataObjectFile(DedicatedFile parent, ushort? id, byte? shortID, 

            // сохранить переданные параметры
            BER.FileControlInformation info) : base(parent, id, shortID, info) {}

        // структура файла
        public override FileStructure FileStructure { get 
        {
            // получить дескриптор файла
            DataObject[] objs = Info[Tag.Context(0x02, ASN1.PC.Primitive)]; 
            
            // проверить наличие дескриптора
            if (objs.Length == 0) return ISO7816.FileStructure.DataObject; 

            // получить содержимое
            byte[] content = objs[0].Content; 
            
            // проверить размер содержимого
            if (content.Length < 1 || (content[0] & 0x80) != 0)
            {
                // указать значение по умолчанию
                return ISO7816.FileStructure.DataObject; 
            }
            // в зависимости установленных битов
            if (((content[0] >> 3) & 0x7) == 0x7)
            {
                // в зависимости установленных битов
                switch (content[0] & 0x7)
                {
                case 0x1: return ISO7816.FileStructure.DataObjectBERTLV;
                case 0x2: return ISO7816.FileStructure.DataObjectSimpleTLV;
                }
            }
            // структура файла неизвестна
            return ISO7816.FileStructure.DataObject;
        }}
        ///////////////////////////////////////////////////////////////////////////
        // прочитать содержимое файла
        ///////////////////////////////////////////////////////////////////////////
        public override Response ReadContent(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient)
        {
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.GetData, 0x00, 0x00, new byte[0], -1
            ); 
            // проверить отсутствие ошибок
            if (!Response.Error(response)) return response; 
            
            // закодировать список тэгов
            byte[] encoded = DataCoding.Encode(new BER.TagList()); 
        
            // выполнить команду
            Response responseBERTLV = channel.SendCommand(secureType, 
                secureClient, INS.GetDataBERTLV, 0x00, 0x00, encoded, -1
            ); 
            // при наличии сокращенного идентификатора
            if (Response.Error(responseBERTLV) && ShortID.HasValue)
            {
                // выполнить команду
                Response responseShort = channel.SendCommand(secureType, 
                    secureClient, INS.GetDataBERTLV, 0x00, ShortID.Value, encoded, -1
                ); 
                // проверить отсутствие ошибок
                if (!Response.Error(responseShort)) responseBERTLV = responseShort; 
            }
            // проверить отсутствие ошибок
            return (!Response.Error(responseBERTLV)) ? responseBERTLV : response; 
        }
        // прочитать файл объектов
        public DataObject[] ReadBERTLVs(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, bool interindustry)
        {
            // определить структуру файла
            FileStructure fileStructure = FileStructure; 
        
            // для файла записей и файла объектов
            if (fileStructure != ISO7816.FileStructure.DataObject && 
                fileStructure != ISO7816.FileStructure.DataObjectBERTLV)
            {
                // при ошибке выбросить исключение
                throw new ResponseException(0x6981); 
            }
            // прочитать содержимое файла
            Response response = ReadContent(channel, secureType, secureClient); 
        
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        
            // раскодировать объекты
            return DataCoding.Decode(response.Data, interindustry); 
        }
        // прочитать файл объектов
        public SimpleTLV[] ReadSimpleTLVs(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient)
        {
            // определить структуру файла
            FileStructure fileStructure = FileStructure; 
        
            // для файла записей и файла объектов
            if (fileStructure != ISO7816.FileStructure.DataObject && 
                fileStructure != ISO7816.FileStructure.DataObjectSimpleTLV)
            {
                // при ошибке выбросить исключение
                throw new ResponseException(0x6981); 
            }
            // прочитать содержимое файла
            Response response = ReadContent(channel, secureType, secureClient); 
        
            // проверить отсутствие ошибок
            ResponseException.Check(response);
        
            // раскодировать объекты
            return SimpleTLV.Decode(response.Data); 
        }
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
            // при наличии сокращенного идентификатора
            if (Response.Error(response) && ShortID.HasValue)
            {
                // выполнить команду
                Response responseShort = channel.SendCommand(secureType, 
                    secureClient, INS.GetDataBERTLV, 0x00, ShortID.Value, encoded, -1
                ); 
                // проверить отсутствие ошибок
                if (!Response.Error(responseShort)) response = responseShort; 
            }
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
            // при наличии сокращенного идентификатора
            if (Response.Error(response) && ShortID.HasValue)
            {
                // выполнить команду
                Response responseShort = channel.SendCommand(secureType, 
                    secureClient, INS.GetDataBERTLV, 0x00, ShortID.Value, encoded, -1
                ); 
                // проверить отсутствие ошибок
                if (!Response.Error(responseShort)) response = responseShort; 
            }
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
            // при наличии сокращенного идентификатора
            if (Response.Error(response) && ShortID.HasValue)
            {
                // выполнить команду
                Response responseShort = channel.SendCommand(secureType, 
                    secureClient, INS.GetDataBERTLV, 0x00, ShortID.Value, encoded, -1
                ); 
                // проверить отсутствие ошибок
                if (!Response.Error(responseShort)) response = responseShort; 
            }
            // проверить отсутствие ошибок
            ResponseException.Check(response); 
            
            // раскодировать объекты
            return DataCoding.Decode(response.Data, interindustry); 
        }
    }
}

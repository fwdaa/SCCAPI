using System;
using System.IO;
using System.Collections.Generic;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Элементарный файл записей
    ///////////////////////////////////////////////////////////////////////////////
    public class RecordFile : ElementaryFile
    {
        // конструктор
        internal RecordFile(DedicatedFile parent, ushort id) : base(parent, id) {}

        // конструктор
        internal RecordFile(DedicatedFile parent, byte shortID) : base(parent, shortID) {}

        // конструктор
        internal RecordFile(DedicatedFile parent, ushort? id, byte? shortID, 
            
            // сохранить переданные параметры
            BER.FileControlInformation info) : base(parent, id, shortID, info) {}

        // структура файла
        public override FileStructure FileStructure { get 
        {
            // получить дескриптор файла
            DataObject[] objs = Info[Tag.Context(0x02, ASN1.PC.Primitive)]; 
            
            // проверить наличие дескриптора
            if (objs.Length == 0) return ISO7816.FileStructure.Record; 

            // получить содержимое
            byte[] content = objs[0].Content; 
            
            // проверить размер содержимого
            if (content.Length < 1 || (content[0] & 0x80) != 0)
            {
                // указать значение по умолчанию
                return ISO7816.FileStructure.Record; 
            }
            // в зависимости установленных битов
            if (((content[0] >> 3) & 0x7) != 0x7)
            {
                // в зависимости установленных битов
                switch (content[0] & 0x7)
                {
                case 0x2: return ISO7816.FileStructure.LinearFixed;
                case 0x3: return ISO7816.FileStructure.LinearFixedTLV;
                case 0x4: return ISO7816.FileStructure.LinearVariable;
                case 0x5: return ISO7816.FileStructure.LinearVariableTLV;
                case 0x6: return ISO7816.FileStructure.CyclicFixed;
                case 0x7: return ISO7816.FileStructure.CyclicFixedTLV;
                }
            }
            // структура файла неизвестна
            return ISO7816.FileStructure.Record;
        }}
        // максимальный размер записи
        public int? MaxRecordSize { get  
        {
            // получить дескриптор файла
            DataObject[] objs = Info[Tag.Context(0x02, ASN1.PC.Primitive)]; 
            
            // проверить наличие дескриптора
            if (objs.Length == 0) return null; byte[] value = new byte[4]; 
            
            // получить содержимое
            byte[] content = objs[0].Content; if (content.Length < 3) return null; 
            
            // скопировать значение
            if (content.Length == 3) value[3] = content[2]; 
            else {
                // скопировать значение
                value[2] = content[2]; value[3] = content[3];
            }
            // раскодировать значение
            if (content.Length == 3) return content[2]; 
            else {
                // раскодировать значение
                return (content[2] << 8) | content[3];
            }
        }}
        // число записей
        public int? RecordCount { get 
        {
            // получить дескриптор файла
            DataObject[] objs = Info[Tag.Context(0x02, ASN1.PC.Primitive)]; 
            
            // проверить наличие дескриптора
            if (objs.Length == 0) return null; byte[] value = new byte[4]; 
            
            // получить содержимое
            byte[] content = objs[0].Content; if (content.Length < 5) return null; 
            
            // раскодировать значение
            if (content.Length == 5) return content[4];
            else {
                // раскодировать значение
                return (content[4] << 8) | content[5];
            }
        }}
        ///////////////////////////////////////////////////////////////////////////
        // Прочитать содержимое файла
        ///////////////////////////////////////////////////////////////////////////
        public override Response ReadContent(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient)
        {
            // получить возможности карты
            BER.CardCapabilities cardCapabilities = channel.Environment.CardCapabilities; 
        
            // определить максимальный размер данных
            int maxPart = (cardCapabilities.SupportExtended) ? 65536 : 256; 
        
            // определить структуру файла
            FileStructure fileStructure = FileStructure; 
        
            // указать направление чтения
            byte p1 = 0x01; byte p2 = (byte)(
                (fileStructure == ISO7816.FileStructure.CyclicFixed || 
                 fileStructure == ISO7816.FileStructure.CyclicFixedTLV) ? 0x06 : 0x05
            ); 
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ReadRecords, p1, p2, new byte[0], -1
            ); 
            // при наличии сокращенного идентификатора
            if (Response.Error(response) && ShortID.HasValue)
            {
                // указать параметр команды
                p2 = (byte)((ShortID.Value << 3) | p2);
            
                // выполнить команду
                Response responseShort = channel.SendCommand(secureType, 
                    secureClient, INS.ReadRecords, p1, p2, new byte[0], -1
                ); 
                // проверить отсутствие ошибок
                if (!Response.Error(responseShort)) response = responseShort; 
            }
            // при отсутствии ошибок
            if (!Response.Error(response))
            {
                // проверить полное считывание данных
                if (response.Data.Length < maxPart) return response; 
            }
            // список записей
            List<byte[]> records = new List<byte[]>(); int number = 1; 
        
            // прочитать запись
            Response responseRecord = ReadRecord(channel, secureType, secureClient, number); 
        
            // для всех записей
            for (; !Response.Error(responseRecord); number++)
            {
                // добавить запись в список
                records.Add(response.Data); 

                // прочитать новую запись
                responseRecord = ReadRecord(channel, secureType, secureClient, number); 
            }
            // проверить кодл ошибки
            if (responseRecord.SW != 0x6A83) return response; 
        
            // объединить записи
            byte[] content = Arrays.Concat(records.ToArray()); 
        
            // вернуть содержимое файла
            return new Response(content, 0x9000); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Прочитать запись файла
        ///////////////////////////////////////////////////////////////////////////
        public byte[][] ReadRecords(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, int recordID)
        {
            // проверить идентификатор записи
            if (recordID < 0 || recordID >= 255) throw new ArgumentException(); 
        
            // создать список записей
            List<Byte[]> records = new List<Byte[]>(); 
        
            // для всех записей
            for (Occurence occurence = Occurence.First; ; occurence = Occurence.Next)
            {
                // прочитать запись
                Response response = ReadRecord(channel, 
                    secureType, secureClient, recordID, occurence
                ); 
                // добавить запись в список
                if (Response.Error(response)) break; records.Add(response.Data);
            }
            // вернуть список записей
            return records.ToArray();
        }
        public Response ReadRecord(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, int recordID, Occurence occurence) 
        {
            // проверить идентификатор записи
            if (recordID < 0 || recordID >= 255) throw new ArgumentException(); 
        
            // указать параметры команды
            byte p1 = (byte)recordID; byte p2 = (byte)(int)occurence; 
        
            // прочитать запись
            return ReadRecord(channel, secureType, secureClient, p1, p2); 
        }
        public Response ReadRecord(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, int number)
        {
            // проверить номер записи
            if (number <= 0 || number >= 255) throw new ArgumentException();
        
            // прочитать запись
            return ReadRecord(channel, secureType, secureClient, (byte)number, 0x04); 
        }
        private Response ReadRecord(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, byte p1, byte p2)
        {
            // получить возможности карты
            BER.CardCapabilities cardCapabilities = channel.Environment.CardCapabilities; 
        
            // определить максимальный размер данных
            int maxPart = (cardCapabilities.SupportExtended) ? 65536 : 256; 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ReadRecords, p1, p2, new byte[0], -1
            ); 
            // при наличии сокращенного идентификатора
            if (Response.Error(response) && ShortID.HasValue)
            {
                // изменить параметр команды
                p2 = (byte)((ShortID.Value << 3) | p2); 
            
                // выполнить команду
                Response responseShort = channel.SendCommand(secureType, 
                    secureClient, INS.ReadRecords, p1, p2, new byte[0], -1
                ); 
                // проверить отсутствие ошибок
                if (!Response.Error(responseShort)) response = responseShort; 
            }
            // при отсутствии ошибок
            if (!Response.Error(response))
            {
                // проверить полное считывание данных
                if (response.Data.Length < maxPart) return response; 
            }
            // прочитать запись полностью
            Response responseBERTLV = ReadRecordBERTLV(
                channel, secureType, secureClient, p1, p2
            ); 
            // проверить отсутствие ошибок
            return (!Response.Error(responseBERTLV)) ? responseBERTLV : response; 
        }
        private Response ReadRecordBERTLV(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, byte p1, byte p2)
        {
            // получить возможности карты
            BER.CardCapabilities cardCapabilities = channel.Environment.CardCapabilities; 
        
            // определить максимальный размер данных
            int maxPart = (cardCapabilities.SupportExtended) ? 65536 : 256; 
        
            // указать начальные условия
            byte[] data = new byte[0]; int offset = 0; 
        
            // закодировать объект смещения
            byte[] encoded = DataCoding.Encode(new BER.DataOffset(offset)); 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ReadRecordsBERTLV, p1, p2, encoded, -1
            ); 
            // при наличии сокращенного идентификатора
            if (Response.Error(response) && ShortID.HasValue)
            {
                // изменить параметр команды
                p2 = (byte)((ShortID.Value << 3) | p2); 
            
                // выполнить команду
                Response responseShort = channel.SendCommand(secureType, 
                    secureClient, INS.ReadRecordsBERTLV, p1, p2, encoded, -1
                ); 
                // проверить отсутствие ошибок
                if (!Response.Error(responseShort)) response = responseShort; 
            }
            // до полного считывания данных
            while (!Response.Error(response))
            {
                // для последних данных
                if (response.Data.Length < maxPart && response.SW == 0x6282) 
                {
                    // изменить код завершения
                    response = new Response(response.Data, 0x9000);
                } 
                // раскодировать объекты
                DataObject[] objs = DataCoding.Decode(response.Data, true); 
            
                // проверить наличие одного объекта
                if (objs.Length != 1) throw new InvalidDataException(); 
            
                // проверить тип содержимого
                if (objs[0].Tag != Tag.DiscretionaryData) throw new InvalidDataException();
            
                // извлечь прочитанные данные
                byte[] responseData = objs[0].Content; 
            
                // изменить размер буфера
                Array.Resize(ref data, data.Length + responseData.Length); 
                
                // скопировать прочитанные данные
                Array.Copy(responseData, 0, data, 
                    data.Length - responseData.Length, responseData.Length
                ); 
                // обработать последние данные в файле
                if (response.Data.Length < maxPart) break; offset += maxPart; 

                // изменить смещение
                encoded = DataCoding.Encode(new BER.DataOffset(offset));

                // выполнить команду
                response = channel.SendCommand(secureType, 
                    secureClient, INS.ReadRecordsBERTLV, p1, p2, encoded, -1
                ); 
            }
            // проверить отсутствие ошибок
            if (Response.Error(response)) return response; 
        
            // вернуть прочитанные данные
            return new Response(data, response.SW);
        }
        ///////////////////////////////////////////////////////////////////////////
        // Записать запись файла
        ///////////////////////////////////////////////////////////////////////////
        public Response WriteRecord(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, int number, byte[] content) 
        {
            // проверить номер записи
            if (number <= 0 || number >= 255) throw new ArgumentException();
        
            // записать запись файла
            Response response = WriteRecord(channel, 
                secureType, secureClient, INS.UpdateRecord, (byte)number, 0x04, content
            ); 
            // проверить отсутствие ошибок
            if (!Response.Error(response)) return response; 
        
            // в зависимости от типа записи
            if (DataCoding.WriteEraseType != WriteType.Proprietary)
            {
                // стереть запись файла
                response = EraseRecord(channel, secureType, secureClient, number); 
            
                // проверить отсутствие ошибок
                if (Response.Error(response)) return response; 
            }
            // записать запись файла
            return WriteRecord(channel, secureType, 
                secureClient, INS.WriteRecord, (byte)number, 0x04, content
            ); 
        }
        private Response WriteRecord(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, byte ins, byte p1, byte p2, byte[] content) 
        {
            // получить возможности карты
            BER.CardCapabilities cardCapabilities = channel.Environment.CardCapabilities; 
        
            // определить максимальный размер данных 
            int maxPart = (cardCapabilities.SupportExtended) ? 65536 : 256; 
        
            // при разбиении на части
            if (!cardCapabilities.SupportChaining && content.Length > maxPart)
            {
                // проверить код операции
                if (ins != INS.UpdateRecord) return new Response(0x6A81); 
        
                // записать запись файла
                return WriteRecordBERTLV(channel, secureType, 
                    secureClient, INS.UpdateRecordBERTLV, p1, p2, 0, content
                ); 
            }
            else {
                // выполнить команду
                Response response = channel.SendCommand(
                    secureType, secureClient, ins, p1, p2, content, 0
                ); 
                // при наличии сокращенного идентификатора
                if (Response.Error(response) && ShortID.HasValue)
                {
                    // изменить код команды
                    p2 = (byte)((ShortID.Value << 3) | p2); 
                
                    // выполнить команду
                    Response responseShort = channel.SendCommand(
                        secureType, secureClient, ins, p1, p2, content, 0
                    ); 
                    // проверить отсутствие ошибок
                    if (!Response.Error(responseShort)) response = responseShort; 
                }
                // проверить отсутствие ошибок
                if (!Response.Error(response) || ins != INS.UpdateRecord) return response; 
            
                // записать запись файла
                Response responseBERTLV = WriteRecordBERTLV(channel, 
                    secureType, secureClient, INS.UpdateRecordBERTLV, p1, p2, 0, content
                ); 
                // проверить отсутствие ошибок
                return (!Response.Error(responseBERTLV)) ? responseBERTLV : response; 
            }
        }
        private Response WriteRecordBERTLV(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, 
            byte ins, byte p1, byte p2, int offset, byte[] content) 
        {
            // получить возможности карты
            BER.CardCapabilities cardCapabilities = channel.Environment.CardCapabilities; 
        
            // закодировать смещение
            byte[] encodedOffset = DataCoding.Encode(new BER.DataOffset(offset)); 

            // при поддержке сцепления
            if (cardCapabilities.SupportChaining)
            {
                // закодировать данные
                byte[] encodedData = DataCoding.Encode(new BER.DiscretionaryData(content));

                // объединить объект смещения и данных
                byte[] encoded = Arrays.Concat(encodedOffset, encodedData); 
            
                // выполнить команду
                Response response = channel.SendCommand(
                    secureType, secureClient, ins, p1, p2, encoded, 0
                ); 
                // при наличии сокращенного идентификатора
                if (Response.Error(response) && ShortID.HasValue)
                {
                    // выполнить команду
                    Response responseShort = channel.SendCommand(
                        secureType, secureClient, ins, p1, ShortID.Value, encoded, 0
                    ); 
                    // проверить отсутствие ошибок
                    if (!Response.Error(responseShort)) response = responseShort; 
                }
                return response; 
            }
            else {
                // определить максимальный размер данных 
                int maxPart = (cardCapabilities.SupportExtended) ? 65536 : 256; 

                // при необходимости разбиения на части
                byte[] buffer = content; if (content.Length > maxPart) 
                {
                    // выделить вспомогательный буфер и скопировать в него данные
                    buffer = new byte[maxPart]; Array.Copy(content, 0, buffer, 0, buffer.Length); 
                }
                // закодировать данные
                byte[] encodedData = DataCoding.Encode(new BER.DiscretionaryData(buffer));

                // при превышении допустимого размера
                while (encodedOffset.Length + encodedData.Length > maxPart)
                {
                    // переразместить буфер
                    Array.Resize(ref buffer, buffer.Length - 
                        (encodedOffset.Length + encodedData.Length - maxPart)
                    ); 
                    // закодировать данные
                    encodedData = DataCoding.Encode(new BER.DiscretionaryData(buffer));
                }
                // объединить объект смещения и данных
                byte[] encoded = Arrays.Concat(encodedOffset, encodedData); 

                // выполнить команду
                Response response = channel.SendCommand(
                    secureType, secureClient, ins, p1, p2, encoded, 0
                ); 
                // при наличии сокращенного идентификатора
                if (Response.Error(response) && ShortID.HasValue)
                {
                    // изменить параметр команды
                    p2 = (byte)((ShortID.Value << 3) | p2); 

                    // выполнить команду
                    Response responseShort = channel.SendCommand(
                        secureType, secureClient, ins, p1, p2, encoded, 0
                    ); 
                    // проверить отсутствие ошибок
                    if (!Response.Error(responseShort)) response = responseShort; 
                }
                // проверить отсутствие ошибок
                if (Response.Error(response)) return response; 

                // проверить завершение записи
                if (buffer.Length == content.Length) return response; offset += buffer.Length;

                // для всех частей 
                for (int ofs = buffer.Length; ofs < content.Length; ofs += buffer.Length, offset += buffer.Length)
                {
                    // выделить буфер требуемого размера
                    buffer = new byte[(content.Length - ofs >= maxPart) ? maxPart : content.Length - ofs]; 

                    // скопировать данные в буфер
                    Array.Copy(content, ofs, buffer, 0, buffer.Length);

                    // закодировать смещение
                    encodedOffset = DataCoding.Encode(new BER.DataOffset(offset)); 

                    // закодировать данные
                    encodedData = DataCoding.Encode(new BER.DiscretionaryData(buffer));

                    // при превышении допустимого размера
                    while (encodedOffset.Length + encodedData.Length > maxPart)
                    {
                        // переразместить буфер
                        Array.Resize(ref buffer, buffer.Length - 
                            (encodedOffset.Length + encodedData.Length - maxPart)
                        ); 
                        // закодировать данные
                        encodedData = DataCoding.Encode(new BER.DiscretionaryData(buffer));
                    }
                    // объединить объект смещения и данных
                    encoded = Arrays.Concat(encodedOffset, encodedData); 

                    // выполнить команду
                    response = channel.SendCommand(
                        secureType, secureClient, ins, p1, p2, encoded, 0
                    );
                    // проверить отсутствие ошибок
                    if (Response.Error(response)) break; 
                }
                return response;
            }
        }
        ///////////////////////////////////////////////////////////////////////////
        // Стереть записи
        ///////////////////////////////////////////////////////////////////////////
        public Response EraseRecord(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, int number)
        {
            // проверить номер записи
            if (number <= 0 || number >= 255) throw new ArgumentException();
        
            // указать параметры команды
            byte p1 = (byte)number; byte p2 = 0x04; 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.EraseRecords, p1, p2, new byte[0], 0
            ); 
            // при наличии сокращенного идентификатора
            if (Response.Error(response) && ShortID.HasValue)
            {
                // изменить параметр команды
                p2 = (byte)((ShortID.Value << 3) | p2); 
            
                // выполнить команду
                Response responseShort = channel.SendCommand(secureType, 
                    secureClient, INS.EraseRecords, p1, p2, new byte[0], 0
                ); 
                // проверить отсут ствие ошибок
                if (!Response.Error(responseShort)) response = responseShort; 
            }
            return response; 
        }
        public Response EraseRecords(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, int fromNumber)
        {
            // проверить номер записи
            if (fromNumber <= 0 || fromNumber >= 255) throw new ArgumentException();
        
            // указать параметры команды
            byte p1 = (byte)fromNumber; byte p2 = 0x05; 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.EraseRecords, p1, p2, new byte[0], 0
            ); 
            // при наличии сокращенного идентификатора
            if (Response.Error(response) && ShortID.HasValue)
            {
                // изменить параметр команды
                p2 = (byte)((ShortID.Value << 3) | p2); 
            
                // выполнить команду
                Response responseShort = channel.SendCommand(secureType, 
                    secureClient, INS.EraseRecords, p1, p2, new byte[0], 0
                ); 
                // проверить отсут ствие ошибок
                if (!Response.Error(responseShort)) response = responseShort; 
            }
            return response; 
        }
    }
}

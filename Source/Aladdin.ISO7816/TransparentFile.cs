using System;
using System.IO;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Элементарный бинарный файл 
    ///////////////////////////////////////////////////////////////////////////////
    public class TransparentFile : ElementaryFile
    {
        // конструктор
        internal TransparentFile(DedicatedFile parent, ushort id) : base(parent, id) {}

        // конструктор
        internal TransparentFile(DedicatedFile parent, byte shortID) : base(parent, shortID) {}

        // конструктор
        internal TransparentFile(DedicatedFile parent, ushort? id, byte? shortID, 
            
            // сохранить переданные параметры
            BER.FileControlInformation info) : base(parent, id, shortID, info) {}

        // структура файла
        public override FileStructure FileStructure { get { return FileStructure.Transparent; }}

        ///////////////////////////////////////////////////////////////////////////
        // Прочитать содержимое файла
        ///////////////////////////////////////////////////////////////////////////
        public override Response ReadContent(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient)
        {
            // прочитать содержимое файла
            return ReadContent(channel, secureType, secureClient, 0, -1); 
        }
        public Response ReadContent(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, int offset, int length)
        {
            // проверить необходимость действий
            if (length == 0) return new Response(new byte[0], 0x9000); 
        
            // прочитать содержимое файла
            Response response = ReadContent0(channel, 
                secureType, secureClient, offset, length
            ); 
            // проверить отсутствие ошибок
            if (!Response.Error(response)) return response;
            
            // прочитать содержимое файла
            Response responseBERTLV = ReadContentBERTLV(
                channel, secureType, secureClient, offset, length
            ); 
            // проверить отсутствие ошибок
            return (!Response.Error(responseBERTLV)) ? responseBERTLV : response;
        }
        // прочитать бинарный файл
        private Response ReadContent0(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, int offset, int length)
        {
            // получить возможности карты
            BER.CardCapabilities cardCapabilities = channel.Environment.CardCapabilities; 
        
            // определить максимальный размер данных
            int maxPart = (cardCapabilities.SupportExtended) ? 65536 : 256; 
        
            // указать параметры команды
            byte p1 = (byte)(offset >> 8); byte p2 = (byte)(offset & 0xFF); byte[] data = new byte[0]; 

            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ReadBinary, p1, p2, new byte[0], -1
            ); 
            // при отсутствии ошибок
            if (!Response.Error(response))
            {
                // до полного считывания данных
                while (!Response.Error(response))
                {
                    // для последних данных
                    if (response.Data.Length < maxPart && response.SW == 0x6282) 
                    {
                        // изменить код завершения
                        response = new Response(response.Data, 0x9000);
                    } 
                    // извлечь прочитанные данные
                    byte[] responseData = response.Data; 

                    // изменить размер буфера
                    Array.Resize(ref data, data.Length + responseData.Length); 

                    // скопировать прочитанные данные
                    Array.Copy(responseData, 0, data, 
                        data.Length - responseData.Length, responseData.Length
                    ); 
                    // при достаточности прочитанных данных
                    if (length >= 0 && data.Length >= length) 
                    {
                        // вернуть прочитанные данные
                        Array.Resize(ref data, length); break;
                    }
                    // обработать последние данные в файле
                    if (response.Data.Length < maxPart) break; offset += maxPart; 

                    // изменить смещение
                    p1 = (byte)(offset >> 8); p2 = (byte)(offset & 0xFF);

                    // выполнить команду
                    response = channel.SendCommand(secureType, 
                        secureClient, INS.ReadBinary, p1, p2, new byte[0], -1
                    ); 
                }
                // проверить отсутствие ошибок
                if (Response.Error(response)) return response;

                // вернуть результат
                return new Response(data, response.SW); 
            }
            // при наличии сокращенного идентификатора
            if (offset <= 255 && ShortID.HasValue)
            {
                // указать параметры команды
                p1 = (byte)(0x80 | ShortID.Value); p2 = (byte)(offset & 0xFF); 
            
                // выполнить команду
                Response responseShort = channel.SendCommand(secureType, 
                    secureClient, INS.ReadBinary, p1, p2, new byte[0], -1
                ); 
                // при отсутствии ошибок
                if (!Response.Error(responseShort))
                {
                    // для последних данных
                    if (responseShort.Data.Length < maxPart && responseShort.SW == 0x6282) 
                    {
                        // изменить код завершения
                        responseShort = new Response(responseShort.Data, 0x9000);
                    } 
                    // при достаточности прочитанных данных
                    if (length >= 0 && responseShort.Data.Length >= length) 
                    {
                        // изменить размер данных
                        data = responseShort.Data; Array.Resize(ref data, length); 

                        // вернуть результат
                        return new Response(data, responseShort.SW);
                    }
                    // обработать последние данные в файле
                    if (responseShort.Data.Length < maxPart) return responseShort; 
                }
            }
            return response; 
        }
        // прочитать бинарный файл
        private Response ReadContentBERTLV(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, int offset, int length)
        {
            // получить возможности карты
            BER.CardCapabilities cardCapabilities = channel.Environment.CardCapabilities; 
        
            // определить максимальный размер данных
            int maxPart = (cardCapabilities.SupportExtended) ? 65536 : 256; 
        
            // закодировать объект смещения
            byte[] encoded = DataCoding.Encode(new BER.DataOffset(offset)); 
        
            // указать параметры команды
            byte p1 = 0x00; byte p2 = 0x00; byte[] data = new byte[0]; 
        
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.ReadBinaryBERTLV, p1, p2, encoded, -1
            ); 
            // при наличии сокращенного идентификатора
            if (Response.Error(response) && ShortID.HasValue)
            {
                // выполнить команду
                p2 = ShortID.Value; Response responseShort = channel.SendCommand(
                    secureType, secureClient, INS.ReadBinaryBERTLV, p1, p2, encoded, -1
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
                // при достаточности прочитанных данных
                if (length >= 0 && data.Length >= length) 
                {
                    // вернуть прочитанные данные
                    Array.Resize(ref data, length); break;
                }
                // проверить завершение данных
                if (response.Data.Length < maxPart) break; offset += maxPart; 
            
                // закодировать смещение
                encoded = DataCoding.Encode(new BER.DataOffset(offset));

                // выполнить команду
                response = channel.SendCommand(secureType, 
                    secureClient, INS.ReadBinaryBERTLV, p1, p2, encoded, -1
                ); 
            }
            // проверить отсутствие ошибок
            if (Response.Error(response)) return response;

            // вернуть результат
            return new Response(data, response.SW); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Записать содержимое файла
        ///////////////////////////////////////////////////////////////////////////
        public Response WriteContent(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, int offset, byte[] content) 
        {
            // проверить необходимость действий
            if (content.Length == 0) return new Response(0x9000); 
        
            // записать данные
            Response response = WriteContent(channel, 
                secureType, secureClient, INS.UpdateBinary, offset, content
            ); 
            // проверить отсутствие ошибок
            if (!Response.Error(response)) return response; 
        
            // в зависимости от типа записи
            if (DataCoding.WriteEraseType != WriteType.Proprietary)
            {
                // стереть содержимое файла
                response = EraseContent(channel, 
                    secureType, secureClient, offset, content.Length
                ); 
                // проверить отсутствие ошибок
                if (Response.Error(response)) return response; 
            }
            // записать содержимое файла
            return WriteContent(channel, 
                secureType, secureClient, INS.WriteBinary, offset, content
            ); 
        }
        private Response WriteContent(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, byte ins, int offset, byte[] content) 
        {
            // записать данные
            Response response = WriteContent0(channel, 
                secureType, secureClient, ins, offset, content
            ); 
            // проверить отсутствие ошибок
            if (!Response.Error(response)) return response; 
            
            // в зависимости от кода операции
            if (ins == INS.UpdateBinary) { ins = INS.UpdateBinaryBERTLV; 
        
                // записать данные
                Response responseBERTLV = WriteContentBERTLV(
                    channel, secureType, secureClient, ins, offset, content
                ); 
                // проверить отсутствие ошибок
                if (!Response.Error(responseBERTLV)) return responseBERTLV; 
            }
            else { ins = INS.WriteBinaryBERTLV; 
            
                // записать данные
                Response responseBERTLV = WriteContentBERTLV(
                    channel, secureType, secureClient, ins, offset, content
                ); 
                // проверить отсутствие ошибок
                if (!Response.Error(responseBERTLV)) return responseBERTLV; 
            }
            return response; 
        }
        private Response WriteContent0(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, byte ins, int offset, byte[] content) 
        {
            // получить возможности карты
            BER.CardCapabilities cardCapabilities = channel.Environment.CardCapabilities; 
        
            // определить максимальный размер данных 
            int maxPart = (cardCapabilities.SupportExtended) ? 65536 : 256; 

            // указать параметры команды
            byte p1 = (byte)(offset >> 8); byte p2 = (byte)(offset & 0xFF); 

            // при отсутствии разбиения на части
            if (cardCapabilities.SupportChaining || content.Length <= maxPart)
            {
                // выполнить команду
                Response response = channel.SendCommand(
                    secureType, secureClient, ins, p1, p2, content, 0
                );         
                // проверить отсутствие ошибок
                if (!Response.Error(response)) return response; 
            
                // при наличии сокращенного идентификатора
                if (offset <= 255 && ShortID.HasValue)
                {
                    // указать параметры команды
                    p1 = (byte)(0x80 | ShortID.Value); p2 = (byte)(offset & 0xFF); 
            
                    // выполнить команду
                    Response responseShort = channel.SendCommand(
                        secureType, secureClient, ins, p1, p2, content, 0
                    ); 
                    // проверить отсутствие ошибок
                    if (!Response.Error(responseShort)) return responseShort; 
                }
                return response; 
            }
            else {
                // выделить вспомогательный буфер и скопировать данные для записи
                byte[] buffer = new byte[maxPart]; Array.Copy(content, 0, buffer, 0, buffer.Length); 

                // выполнить команду
                Response response = channel.SendCommand(
                    secureType, secureClient, ins, p1, p2, buffer, 0
                );         
                // проверить отсутствие ошибок
                if (Response.Error(response)) return response; 

                // проверить завершение записи
                if (buffer.Length == content.Length) return response; offset += buffer.Length;

                // для всех оставшихся частей 
                for (int ofs = buffer.Length; ofs < content.Length; ofs += buffer.Length, offset += buffer.Length)
                {
                    // указать параметры команды
                    p1 = (byte)(offset >> 8); p2 = (byte)(offset & 0xFF); 

                    // скорректировать размер буфера
                    if (content.Length - ofs < maxPart) buffer = new byte[content.Length - ofs]; 

                    // скопировать данные в буфер
                    Array.Copy(content, ofs, buffer, 0, buffer.Length);

                    // выполнить команду
                    response = channel.SendCommand(secureType, secureClient, ins, p1, p2, buffer, 0);         

                    // проверить отсутствие ошибок
                    if (Response.Error(response)) break; 
                }
                return response; 
            }
        }
        private Response WriteContentBERTLV(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, byte ins, int offset, byte[] content) 
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
                    secureType, secureClient, ins, 0x00, 0x00, encoded, 0
                ); 
                // при наличии сокращенного идентификатора
                if (Response.Error(response) && ShortID.HasValue)
                {
                    // выполнить команду
                    Response responseShort = channel.SendCommand(
                        secureType, secureClient, ins, 0x00, ShortID.Value, encoded, 0
                    ); 
                    // проверить отсутствие ошибок
                    if (!Response.Error(responseShort)) response = responseShort; 
                }
                return response; 
            }
            else {  
                // определить максимальный размер данных 
                int maxPart = (cardCapabilities.SupportExtended) ? 65536 : 256; 
        
                // при необходимости передачи по частям
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
                byte[] encoded = Arrays.Concat(encodedOffset, encodedData); byte p2 = 0x00; 
            
                // выполнить команду
                Response response = channel.SendCommand(
                    secureType, secureClient, ins, 0x00, p2, encoded, 0
                ); 
                // при наличии сокращенного идентификатора
                if (Response.Error(response) && ShortID.HasValue)
                {
                    // выполнить команду
                    p2 = ShortID.Value; Response responseShort = channel.SendCommand(
                        secureType, secureClient, ins, 0x00, p2, encoded, 0
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
                        secureType, secureClient, ins, 0x00, p2, encoded, 0
                    );
                    // проверить отсутствие ошибок
                    if (Response.Error(response)) break; 
                }
                return response;
            }
        }
        ///////////////////////////////////////////////////////////////////////////
        // Стереть содержимое файла
        ///////////////////////////////////////////////////////////////////////////
        private Response EraseContent(LogicalChannel channel, 
            SecureType secureType, SecureClient secureClient, int offset, int length)
        {
            // проверить необходимость действий
            if (length == 0) return new Response(0x9000); 
        
            // указать параметры команды
            byte p1 = (byte)(offset >> 8); byte p2 = (byte)(offset & 0xFF); 
        
            // закодировать граничное смещение
            byte[] encoded = new byte[0]; if (length >= 0)
            {
                // закодировать граничное смещение
                encoded = new BER.DataOffset(offset + length).Content; 
            }
            // выполнить команду
            Response response = channel.SendCommand(secureType, 
                secureClient, INS.EraseBinary, p1, p2, encoded, 0
            ); 
            // проверить отсутствие ошибок
            if (!Response.Error(response)) return response; 
        
            // при наличии сокращенного идентификатора
            if (offset <= 255 && ShortID.HasValue)
            {
                // указать параметры команды
                p1 = (byte)(0x80 | ShortID.Value); p2 = (byte)(offset & 0xFF); 
            
                // выполнить команду
                Response responseShort = channel.SendCommand(
                    secureType, secureClient, INS.EraseBinary, p1, p2, encoded, 0
                ); 
                // проверить отсутствие ошибок
                if (!Response.Error(responseShort)) return responseShort; 
            }
            // закодировать смещение
            encoded = DataCoding.Encode(new BER.DataOffset(offset)); if (length >= 0)
            {
                // закодировать граничное смещение
                byte[] encodedLimit = DataCoding.Encode(new BER.DataOffset(offset + length)); 
            
                // объединить два смещения
                encoded = Arrays.Concat(encoded, encodedLimit); 
            }
            // выполнить команду
            Response responseBERTLV = channel.SendCommand(secureType, 
                secureClient, INS.EraseBinaryBERTLV, 0x00, 0x00, encoded, 0
            ); 
            // проверить отсутствие ошибок
            if (!Response.Error(responseBERTLV)) return responseBERTLV;

            // при наличии сокращенного идентификатора
            if (ShortID.HasValue)
            {
                // выполнить команду
                Response responseShort = channel.SendCommand(secureType, 
                    secureClient, INS.EraseBinaryBERTLV, 0x00, ShortID.Value, encoded, 0
                ); 
                // проверить отсутствие ошибок
                if (!Response.Error(responseShort)) return responseShort; 
            }
            return response;
        }
    }
}

using System;
using System.Collections;
using System.Collections.Generic;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////
    // Описание возможностей смарт-карты
    ///////////////////////////////////////////////////////////////////////////
    public class CardEnvironment : IEnumerable<DataObject>
    {
        // схема кодирования и набор объектов
        private TagScheme tagScheme; private Dictionary<Tag, DataObject> objects;

        // конструктор
        public CardEnvironment(TagScheme tagScheme, Dictionary<Tag, DataObject> objects) 
        { 
            // сохранить переданные параметры
            this.tagScheme = tagScheme; this.objects = objects; 
        }
        // конструктор
        public CardEnvironment(TagScheme tagScheme, params DataObject[] objects) 
        { 
            // сохранить переданные параметры
            this.tagScheme = tagScheme; this.objects = new Dictionary<Tag, DataObject>(); 

            // для всех объектов
            foreach (DataObject obj in objects)
            {
                // проверить отсутствие элемента
                if (this.objects.ContainsKey(obj.Tag)) continue; 
            
                // добавить элемент в список
                this.objects.Add(obj.Tag, obj); 
            }
        }
	    // перечислитель объектов
	    IEnumerator IEnumerable.GetEnumerator() 
        { 
	        // перечислитель объектов
            return ((IEnumerable<DataObject>)this).GetEnumerator(); 
        }
	    // перечислитель объектов
        public virtual IEnumerator<DataObject> GetEnumerator() 
        { 
	        // перечислитель объектов
            return objects.Values.GetEnumerator(); 
        }
	    // получить элемент коллекции
	    public DataObject this[Tag tag] { get 
        { 
	        // получить элемент коллекции
            return (objects.ContainsKey(tag)) ? objects[tag] : null; 
        }}
        // добавить объекты
        public CardEnvironment Combine(DataObject[] objects)
        {
            // скопировать объекты
            Dictionary<Tag, DataObject> map = new Dictionary<Tag, DataObject>(this.objects); 
        
            // для всех объектов
            foreach (DataObject obj in objects)
            {
                // добавить элемент в список
                if (!map.ContainsKey(obj.Tag)) map.Add(obj.Tag, obj);
            }
            // вернуть объединение объектов
            return new CardEnvironment(TagScheme, map); 
        }
        // добавить объекты из EF.ATR
        public CardEnvironment CombineEFATR(LogicalChannel channel)
        {
            // получить требуемый объект
            BER.CardServiceData cardServiceData = CardServiceData; 

            // проверить наличие объекта
            if (cardServiceData == null) return this; 
        
            // получить содержимое объекта
            byte[] content = cardServiceData.Content; ushort id = 0x2F01; 
        
            // проверить наличие EF.ATR
            if (content.Length != 1 || (content[0] & 0x10) == 0) return this; 
        
            // выделить мастер-файл
            DedicatedFile masterFile = DedicatedFile.Select(channel, new ushort[] { 0x3F00 }); 
        
            // в зависимости от типа файла
            Response response = null; switch (content[0] & 0x07)
            {
            // прочитать содержимое файла
            case 0x00: response = masterFile.ReadRecordFile(channel, id, SecureType.None, null); break; 
            case 0x02: response = masterFile.ReadDataFile  (channel, id, SecureType.None, null); break; 
            case 0x04: response = masterFile.ReadBinaryFile(channel, id, SecureType.None, null); break; 
            default  : response = masterFile.ReadFile      (channel, id, SecureType.None, null); break; 
            }
            // проверить отсутствие ошибок
            ResponseException.Check(response); 

            // добавить объекты
            return Combine(DataCoding.Decode(response.Data, true)); 
        }
        // способ кодирования данных
        public DataCoding DataCoding { get 
        {
            // вернуть способ кодирования данных   
            return CardCapabilities.DataCoding(TagScheme); 
        }}
        // схема кодирования
        public TagScheme TagScheme { get 
        {
            // найти объект
            DataObject obj = this[Tag.CompatibleTagScheme]; if (obj != null)
            { 
                // раскодировать объект
                return TagScheme.DecodeTagScheme(obj.Tag, obj.Content); 
            }
            // найти объект
            obj = this[Tag.CoexistentTagScheme]; if (obj != null)
            { 
                // раскодировать объект
                return new TagScheme.Coexistent(obj.Content); 
            }
            return tagScheme; 
        }}
        // код страны
        public BER.CountryIndicator CountryIndicator { get 
        { 
            // найти объект
            DataObject obj = this[Tag.CountryIndicator]; 

            // раскодировать объект
            return (obj != null) ? new BER.CountryIndicator(obj.Content) : null; 
        }}
        // идентификатор издателя карты
        public BER.IssuerIndicator IssuerIndicator { get 
        { 
            // найти объект
            DataObject obj = this[Tag.IssuerIndicator]; 

            // раскодировать объект
            return (obj != null) ? new BER.IssuerIndicator(obj.Content) : null; 
        }}
        public BER.CardServiceData CardServiceData { get  
        {
            // найти объект
            DataObject obj = this[Tag.CardServiceData]; 

            // раскодировать объект
            return (obj != null) ? new BER.CardServiceData(obj.Content) : null; 
        }}
        public BER.InitialAccessData InitialAccessData { get 
        {
            // найти объект
            DataObject obj = this[Tag.InitialAccessData]; 

            // раскодировать объект
            return (obj != null) ? new BER.InitialAccessData(obj.Content) : null; 
        }}
        public BER.CardIssuerData CardIssuerData { get  
        {
            // найти объект
            DataObject obj = this[Tag.CardIssuerData]; 

            // раскодировать объект
            return (obj != null) ? new BER.CardIssuerData(obj.Content) : null; 
        }}
        public BER.PreIssuingData PreIssuingData { get  
        {
            // найти объект
            DataObject obj = this[Tag.PreIssuingData]; 

            // раскодировать объект
            return (obj != null) ? new BER.PreIssuingData(obj.Content) : null; 
        }}
        public BER.CardCapabilities CardCapabilities { get 
        { 
            // найти объект
            DataObject obj = this[Tag.CardCapabilities]; 
        
            // указать значение по умолчанию
            if (obj == null) return new BER.CardCapabilities(new byte[1]); 

            // раскодировать объект
            return new BER.CardCapabilities(obj.Content); 
        }}
        // фаза жизненного цикла
        public BER.LifeCycle LifeCycle { get  
        { 
            // найти объект
            Tag tag = Tag.LifeCycle; DataObject obj = this[tag]; 

            // раскодировать объект
            return (obj != null) ? new BER.LifeCycle(tag, obj.Content) : null; 
        }}
        public BER.ApplicationIdentifier ApplicationIdentifier { get 
        {
            // найти объект
            DataObject obj = this[Tag.ApplicationIdentifier]; 

            // раскодировать объект
            return (obj != null) ? BER.ApplicationIdentifier.Decode(obj.Content) : null; 
        }}
	    // отправить команду смарт-карте
	    public Response SendCommand(CardSession session, 
            byte cla, byte ins, byte p1, byte p2, byte[] data, int ne)
        {
            // при коротком ответе без сцепления
            if (0 <= ne && ne <= 256 && (cla & 0x10) == 0 && data.Length <= 255)
            {
                // выполнить команду
                return SendCommand(session, new Command(cla, ins, p1, p2, data, ne)); 
            }
            // указать начальные условия
            Response response = new Response(0x6A81); int maxPart = 255; 
        
            // получить требуемые свойства
            BER.CardCapabilities cardCapabilities = session.Environment.CardCapabilities; 

            // при отсутствии требуемого свойства
            if (cardCapabilities == null || cardCapabilities.Content.Length < 3)
            {
                // проверить отсутствие сцепления
                if ((cla & 0x10) != 0) return new Response(0x6884); 
            
                // проверить размер данных
                if (data.Length > maxPart) return response; 
            
                // скорректировать размер
                if (ne < 0 || (maxPart + 1) < ne) ne = maxPart + 1; 

                // выполнить команду
                return SendCommand(session, new Command(cla, ins, p1, p2, data, ne)); 
            }
            else {
                // проверить возможность использования длинных размеров
                if ((cardCapabilities.Data(2) & 0x40) != 0) maxPart = 65535;
            
                // скорректировать размер
                if (ne < 0 || (maxPart + 1) < ne) ne = maxPart + 1; 
            
                // при невозможности сцепления
                if ((cardCapabilities.Data(2) & 0x80) == 0)
                {
                    // проверить отсутствие сцепления
                    if ((cla & 0x10) != 0) return new Response(0x6884); 
                
                    // проверить размер данных
                    if (data.Length > maxPart) return response; 

                    // выполнить команду
                    return SendCommand(session, new Command(cla, ins, p1, p2, data, ne)); 
                }
                // при отсутствии необходимости разбиения
                else if (data.Length <= maxPart)
                {
                    // выполнить команду
                    return SendCommand(session, new Command(cla, ins, p1, p2, data, ne)); 
                }
                else { 
                    // выделить буфер максимального размера
                    byte[] buffer = new byte[maxPart]; byte chainCLA = (byte)(cla | 0x10); 
                
                    // для всех непоследних частей данных
                    int offset = 0; for (; offset < data.Length - maxPart; offset += maxPart)
                    {
                        // скопировать данные в буфер
                        Array.Copy(data, offset, buffer, 0, maxPart);
                    
                        // выполнить команду
                        response = SendCommand(session, new Command(chainCLA, ins, p1, p2, buffer, 0));
                    
                        // проверить отсутствие ошибок
                        if (Response.Error(response)) return response; 
                    }
                    // выделить буфер требуемого размера
                    buffer = new byte[data.Length - offset]; 

                    // скопировать данные в буфер
                    Array.Copy(data, offset, buffer, 0, buffer.Length);

                    // выполнить команду
                    return SendCommand(session, new Command(cla, ins, p1, p2, buffer, ne));
                }
            }        
        }
		// отправить команду смарт-карте
		public Response SendCommand(CardSession session, Command command)
        {
            // раскодировать результат
            ISO7816.Response response = new Response(session.SendCommand(command.Encoded)); 

	        // при неправильном размере ответа
	        if ((response.SW >> 8) == 0x6C) { int Ne = response.SW & 0xFF; 

		        // указать команду с правильным рамером
		        Command nextCommand = new Command(command.CLA, 
			        command.INS, command.P1, command.P2, command.Data, Ne
		        ); 
		        // выполнить команду
		        return SendCommand(session, nextCommand);
	        }
            // указать начальные условия
            byte[] data = response.Data;

	        // при наличии дополнительных данных
	        while ((response.SW >> 8) == 0x61) { int Ne = response.SW & 0xFF; 

                // при отсутствии размера данных
                if (Ne == 0) { BER.CardCapabilities cardCapabilities = CardCapabilities; 
        
                    // указать требуемый размер данных
                    Ne = (cardCapabilities.SupportExtended) ? 65536 : 256;
                }
		        // создать команду GET RESPONSE
		        Command nextCommand = new Command(
			        command.CLA, INS.GetResponse, 0x00, 0x00, new byte[0], Ne
		        ); 
		        // выполнить команду
		        response = SendCommand(session, nextCommand); 

		        // создать буфер требуемого размера
		        Array.Resize(ref data, data.Length + response.Data.Length); 

		        // скопировать данные из второго ответа
		        Array.Copy(response.Data, 0, data, 
                    data.Length - response.Data.Length, response.Data.Length
                );
                // переустановить ответ
                response = new Response(data, response.SW); 
	        }
            // проверить возможность ответа
            if (session.Client == null) return response; 
        
            // при запросе от карты
            if (0x6402 <= response.SW && response.SW <= 0x6480) 
            {
                // обработать запрос от карты
                response = session.Client.reply(session, command, response.SW); 
        
                // повторить исходную команду
                if (!Response.Error(response)) response = SendCommand(session, command);
            }
            // при запросе от карты
            else if (0x6202 <= response.SW && response.SW <= 0x6280) 
            {
                // обработать запрос от карты
                response = session.Client.reply(session, command, response.SW); 
            }
            return response; 
        }

    }
}

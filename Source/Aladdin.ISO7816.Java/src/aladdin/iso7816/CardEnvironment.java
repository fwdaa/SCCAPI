package aladdin.iso7816;
import aladdin.iso7816.ber.*;
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Описание возможностей смарт-карты
///////////////////////////////////////////////////////////////////////////
public class CardEnvironment implements Iterable<DataObject>
{
    // схема кодирования и набор объектов
    private final TagScheme tagScheme; private final Map<Tag, DataObject> objects;
    
    // конструктор
    public CardEnvironment(TagScheme tagScheme, Map<Tag, DataObject> objects) 
    {  
        // сохранить переданные параметры
        this.tagScheme = tagScheme; this.objects = objects; 
    } 
    // конструктор
    public CardEnvironment(TagScheme tagScheme, DataObject... objects) 
    {  
        // сохранить переданные параметры
        this.tagScheme = tagScheme; this.objects = new HashMap<Tag, DataObject>(); 
        
        // для всех объектов
        for (DataObject obj : objects)
        {
            // проверить отсутствие элемента
            if (this.objects.containsKey(obj.tag())) continue; 
            
            // добавить элемент в список
            this.objects.put(obj.tag(), obj); 
        }
    } 
    // перечислитель объектов
    @Override public Iterator<DataObject> iterator() { return objects.values().iterator(); }
    
    // получить элемент коллекции
    public final DataObject get(Tag tag) { return objects.get(tag); }
    
    // добавить объекты
    public final CardEnvironment combine(DataObject[] objects) throws IOException
    {
        // скопировать объекты
        Map<Tag, DataObject> map = new HashMap<Tag, DataObject>(this.objects); 
        
        // для всех объектов
        for (DataObject obj : objects)
        {
            // добавить элемент в список
            if (!map.containsKey(obj.tag())) map.put(obj.tag(), obj);
        }
        // вернуть объединение объектов
        return new CardEnvironment(tagScheme(), map); 
    }
    // добавить объекты из EF.ATR
    public final CardEnvironment combineEFATR(LogicalChannel channel) throws IOException
    {
        // получить требуемый объект
        CardServiceData cardServiceData = cardServiceData(); 

        // проверить наличие объекта
        if (cardServiceData == null) return this; short id = 0x2F01; 
        
        // получить содержимое объекта
        byte[] content = cardServiceData.content(); 
        
        // проверить наличие EF.ATR
        if (content.length != 1 || (content[0] & 0x10) == 0) return this; 
        
        // выделить мастер-файл
        DedicatedFile masterFile = DedicatedFile.select(channel, new short[] { 0x3F00 }); 
        
        // в зависимости от типа файла
        Response response; switch (content[0] & 0x07)
        {
        // прочитать содержимое файла
        case 0x00: response = masterFile.readRecordFile    (channel, id, SecureType.NONE, null); break; 
        case 0x02: response = masterFile.readDataObjectFile(channel, id, SecureType.NONE, null); break; 
        case 0x04: response = masterFile.readBinaryFile    (channel, id, SecureType.NONE, null); break; 
        default  : response = masterFile.readFile          (channel, id, SecureType.NONE, null); break; 
        }
        // проверить отсутствие ошибок
        ResponseException.check(response); 
        
        // добавить объекты
        return combine(dataCoding().decode(response.data, true)); 
    }
    // способ кодирования данных
    public final DataCoding dataCoding() throws IOException
    {
        // вернуть способ кодирования данных   
        return cardCapabilities().dataCoding(tagScheme()); 
    }
    // схема кодирования
    public final TagScheme tagScheme() throws IOException
    {
        // найти объект
        DataObject obj = get(Tag.COMPATIBLE_TAG_SCHEME); if (obj != null) 
        {
            // раскодировать объект
            return TagScheme.decodeTagScheme(obj.tag(), obj.content()); 
        }
        // найти объект
        obj = get(Tag.COEXISTENT_TAG_SCHEME); if (obj != null) 
        {
            // раскодировать объект
            return new TagScheme.Coexistent(obj.content()); 
        }
        return tagScheme; 
    }
    // код страны
    public final CountryIndicator countryIndicator() throws IOException
    { 
        // найти объект
        DataObject obj = get(Tag.COUNTRY_INDICATOR); 

        // раскодировать объект
        return (obj != null) ? new CountryIndicator(obj.content()) : null; 
    }
    // идентификатор издателя карты
    public final IssuerIndicator issuerIndicator() 
    { 
        // найти объект
        DataObject obj = get(Tag.ISSUER_INDICATOR); 

        // раскодировать объект
        return (obj != null) ? new IssuerIndicator(obj.content()) : null; 
    }
    public final CardServiceData cardServiceData() throws IOException 
    {
        // найти объект
        DataObject obj = get(Tag.CARD_SERVICE_DATA); 

        // раскодировать объект
        return (obj != null) ? new CardServiceData(obj.content()) : null; 
    }
    public final InitialAccessData initialAccessData() throws IOException
    {
        // найти объект
        DataObject obj = get(Tag.INITIAL_ACCESS_DATA); 

        // раскодировать объект
        return (obj != null) ? new InitialAccessData(obj.content()) : null; 
    }
    public final CardIssuerData cardIssuerData() 
    {
        // найти объект
        DataObject obj = get(Tag.CARD_ISSUER_DATA); 

        // раскодировать объект
        return (obj != null) ? new CardIssuerData(obj.content()) : null; 
    }
    public final PreIssuingData preIssuingData() 
    {
        // найти объект
        DataObject obj = get(Tag.PRE_ISSUING_DATA); 

        // раскодировать объект
        return (obj != null) ? new PreIssuingData(obj.content()) : null; 
    }
    public final CardCapabilities cardCapabilities()
    { 
        // найти объект
        DataObject obj = get(Tag.CARD_CAPABILITIES); 
        
        // указать значение по умолчанию
        if (obj == null) return new CardCapabilities(new byte[1]); 

        // раскодировать объект
        return new CardCapabilities(obj.content()); 
    }
    // фаза жизненного цикла
    public final LifeCycle lifeCycle() 
    { 
        // найти объект
        Tag tag = Tag.LIFE_CYCLE; DataObject obj = get(tag); 

        // раскодировать объект
        return (obj != null) ? new LifeCycle(tag, obj.content()) : null; 
    }
    public final ApplicationIdentifier applicationIdentifier() throws IOException
    {
        // найти объект
        DataObject obj = get(Tag.APPLICATION_IDENTIFIER); 

        // раскодировать объект
        return (obj != null) ? ApplicationIdentifier.decode(obj.content()) : null; 
    }
	// отправить команду смарт-карте
	public final Response sendCommand(CardSession session, 
        byte cla, byte ins, byte p1, byte p2, byte[] data, int ne) throws IOException
    {
        // при коротком ответе без сцепления
        if (0 <= ne && ne <= 256 && (cla & 0x10) == 0 && data.length <= 255)
        {
            // выполнить команду
            return sendCommand(session, new Command(cla, ins, p1, p2, data, ne)); 
        }
        // получить требуемые свойства
        CardCapabilities cardCapabilities = cardCapabilities(); 
        
        // проверить возможность использования длинных размеров
        int maxPart = (cardCapabilities.supportExtended()) ? 65535 : 255;
        
        // скорректировать размер
        if (ne < 0 || (maxPart + 1) < ne) ne = maxPart + 1; 
        
        // при невозможности сцепления
        if (!cardCapabilities.supportChaining())
        {
            // проверить отсутствие сцепления
            if ((cla & 0x10) != 0) return new Response((short)0x6884); 
        
            // проверить размер данных
            if (data.length > maxPart) return new Response((short)0x6A81); 
        }
        // при отсутствии необходимости разбиения
        if (data.length <= maxPart)
        {
            // выполнить команду
            return sendCommand(session, new Command(cla, ins, p1, p2, data, ne)); 
        }
        // выделить буфер максимального размера
        byte[] buffer = new byte[maxPart]; byte chainCLA = (byte)(cla | 0x10); 
                
        // для всех непоследних частей данных
        int offset = 0; for (; offset < data.length - maxPart; offset += maxPart)
        {
            // скопировать данные в буфер
            System.arraycopy(data, offset, buffer, 0, maxPart);
                    
            // выполнить команду
            Response response = sendCommand(session, new Command(chainCLA, ins, p1, p2, buffer, 0));
                    
            // проверить отсутствие ошибок
            if (Response.error(response)) return response; 
        }
        // выделить буфер требуемого размера
        buffer = new byte[data.length - offset]; 

        // скопировать данные в буфер
        System.arraycopy(data, offset, buffer, 0, buffer.length);

        // выполнить команду
        return sendCommand(session, new Command(cla, ins, p1, p2, buffer, ne));
    }
	// отправить команду смарт-карте
	public final Response sendCommand(CardSession session, Command command) throws IOException
    {
	    // отправить команду смарт-карте
        Response response = new Response(session.sendCommand(command.encoded())); 

	    // при неправильном размере ответа
	    if (((response.SW >>> 8) & 0xFF) == 0x6C) { int Ne = response.SW & 0xFF; 

            // указать команду с правильным размером
		    Command nextCommand = new Command(command.CLA, 
			    command.INS, command.P1, command.P2, command.data, Ne
		    ); 
		    // выполнить команду
		    return sendCommand(session, nextCommand);
        }
        // указать начальные условия
        byte[] data = response.data;
        
	    // при наличии дополнительных данных
	    while (((response.SW >>> 8) & 0xFF) == 0x61) { int Ne = response.SW & 0xFF; 
        
            // при отсутствии размера данных
            if (Ne == 0) { CardCapabilities cardCapabilities = cardCapabilities(); 
        
                // указать требуемый размер данных
                Ne = (cardCapabilities.supportExtended()) ? 65536 : 256;
            }
		    // создать команду GET RESPONSE
		    command = new Command(command.CLA, INS.GET_RESPONSE, (byte)0x00, (byte)0x00, new byte[0], Ne); 
            
	        // выполнить команду
	        response = new Response(session.sendCommand(command.encoded())); 

	        // создать буфер требуемого размера
	        data = Arrays.copyOf(data, data.length + response.data.length); 

	        // скопировать данные из второго ответа
	        System.arraycopy(response.data, 0, data, data.length - response.data.length, response.data.length);
            
            // переустановить ответ
            response = new Response(data, response.SW); 
	    }
        // проверить возможность ответа
        if (session.client() == null) return response; 
        
        // при запросе от карты
        if (0x6402 <= response.SW && response.SW <= 0x6480) 
        {
            // обработать запрос от карты
            response = session.client().reply(session, command, response.SW); 
        
            // повторить исходную команду
            if (!Response.error(response)) response = sendCommand(session, command);
        }
        // при запросе от карты
        else if (0x6202 <= response.SW && response.SW <= 0x6280) 
        {
            // обработать запрос от карты
            response = session.client().reply(session, command, response.SW); 
        }
        return response; 
    }
}

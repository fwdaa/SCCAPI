package aladdin.iso7816;
import aladdin.*; 
import aladdin.iso7816.ber.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Логический канал
///////////////////////////////////////////////////////////////////////////////
public class LogicalChannel extends RefObject
{
    // среда окружения смарт-карты
    private CardEnvironment environment; 
    // сеанс взаимодействия со смарт-картой и номер канала
    private final CardSession session; private final int ordinal; 
    
    // конструктор
    protected LogicalChannel() 
    {
        // сохранить переданные параметры
        this.environment = null; this.session = null; this.ordinal = 0;
    }
    // конструктор
    private LogicalChannel(CardEnvironment environment, 
        CardSession session, int ordinal) throws IOException
    {
        // проверить корректность номера
        if (ordinal <= 0 || ordinal > 19) throw new IllegalArgumentException(); 
        
        // сохранить переданные параметры
        this.environment = environment; this.ordinal = ordinal;
        
        // сохранить переданные параметры
        this.session = RefObject.addRef(session);         
        
        // обработать файл EF.ATR
        this.environment = environment.combineEFATR(this); 
    }
    // деструктор
    @Override protected void onClose() throws IOException
    { 
        // обработать основной канал
        if (ordinal == 0) { super.onClose(); return; }
         
        // закрыть логический канал
        sendCommand(INS.MANAGE_CHANNEL, (byte)0x80, (byte)ordinal, new byte[0], 0); 
        
        // освободить выделенные ресурсы
        RefObject.release(session); super.onClose();  
    }
    // возможности смарт-карты
    public CardEnvironment environment() { return environment; }
    // сеанс взаимодействия со смарт-картой
    public CardSession session() { return session; }
    
    // номер канала
    public final int ordinal() { return ordinal; }
    
    // создать логический канал
    public final LogicalChannel create() throws IOException
    {
        // указать начальные условия
        Response response = new Response((short)0x6881); 
        
        // получить требуемый объект
        CardCapabilities cardCapabilities = environment().cardCapabilities(); 

        // при поддержке создания динамического канала
        if ((cardCapabilities.data(2) & 0x08) != 0)
        {
            // открыть логический канал
            response = sendCommand(
                INS.MANAGE_CHANNEL, (byte)0x00, (byte)0x00, new byte[0], 1); 
            
            // проверить отсутствие ошибок
            ResponseException.check(response);
            
            // проверить размер поля
            if (response.data.length != 1) throw new IOException(); 
        
            // вернуть объект канала
            return new LogicalChannel(environment(), session(), response.data[0]); 
        }
        // при поддержке создания статического канала
        else if ((cardCapabilities.data(2) & 0x10) != 0)
        {
            // определить число каналов
            int channels = (cardCapabilities.data(2) & 0x07); 
            
            // скорректировать число каналов
            channels = (channels == 7) ? 20 : (channels + 1); 
            
            // для всех каналов
            for (byte i = 1; i < channels; i++)
            {
                // создать логический канал
                response = sendCommand(
                    INS.MANAGE_CHANNEL, (byte)0x00, i, new byte[0], 0
                ); 
                // проверить отсутствие ошибок
                if (!Response.error(response))
                {
                    // вернуть объект канала
                    return new LogicalChannel(environment(), session(), i); 
                }
            }
        }
        // при ошибке выбросить исключение
        throw new ResponseException(response.SW);
    }
    // открыть логический канал
    public final LogicalChannel create(int ordinal) throws IOException
    {
        // проверить корректность параметров
        if (ordinal <= 0 || ordinal > 19) throw new IllegalArgumentException(); 
        
        // получить требуемый объект
        CardCapabilities cardCapabilities = environment().cardCapabilities(); 

        // приверить поддержку создания каналов
        if ((cardCapabilities.data(2) & 0x18) == 0) 
        {
            // при ошибке выбросить исключение
            throw new ResponseException((short)0x6881); 
        }
        // проверить поддержку создания каналов
        if ((cardCapabilities.data(2) & 0x10) == 0) 
        {
            // при ошибке выбросить исключение
            throw new ResponseException((short)0x6A81); 
        }
        // открыть логический канал
        Response response = sendCommand(
            INS.MANAGE_CHANNEL, (byte)0x00, (byte)ordinal, new byte[0], 0
        ); 
        // проверить отмутствие ошибок
        ResponseException.check(response);
        
        // вернуть объект канала
        return new LogicalChannel(environment(), session(), ordinal); 
    }
    // выполнить команду
	public final Response sendCommand(
        byte ins, byte p1, byte p2, byte[] data, int ne) throws IOException
    {
        // выполнить команду
        return sendCommand(SecureType.NONE, null, ins, p1, p2, data, ne); 
    }
    // выполнить команду
	public final Response sendCommand(int secureType, SecureClient secureClient, 
        byte ins, byte p1, byte p2, byte[] data, int ne) throws IOException
    {
        // для первых каналов
        byte cla; if (ordinal <= 3) cla = (byte)(ordinal | ((secureType & 0x3) << 2)); 
        
        else switch (secureType & SecureType.SECURE_HEADER)
        {
        // указать класс команды
        case SecureType.NONE         : cla = (byte)((ordinal - 4) | 0x40); break; 
        case SecureType.SECURE       : cla = (byte)((ordinal - 4) | 0x60); break; 
        case SecureType.SECURE_HEADER: cla = (byte)((ordinal - 4) | 0x60); break; 

        // обработать возможную ошибку
        default: return new Response(new byte[0], (short)0x6A81); 
        }
        // при отсутствии защиты
        if (secureClient == null || secureType == SecureType.NONE || secureType == SecureType.PROPRIETARY)
        {
            // выполнить команду
            return environment().sendCommand(session(), cla, ins, p1, p2, data, ne); 
        }
        else {
            // указать криптографическую среду
            SecurityEnvironment securityEnvironment = SecurityEnvironment.CURRENT; 
            
            // получить параметры алгоритмов
            CRT.CT  cipherParameters = securityEnvironment.getCipherParameters(this); 
            CRT.CCT    macParameters = securityEnvironment.getMacParameters   (this); 
            CRT.DST   signParameters = securityEnvironment.getSignParameters  (this); 
            
            // выполнить защиту сообщения
            data = secureClient.protect(environment(), secureType, 
                cipherParameters, macParameters, signParameters, cla, ins, p1, p2, data, ne
            ); 
            // выполнить команду
            Response response = environment().sendCommand(session(), cla, ins, p1, p2, data, -1); 
            
            // снять защиту сообщения
            return secureClient.unprotect(environment(), 
                cipherParameters, macParameters, signParameters, response
            ); 
        }
    }
    // выполнить команду
	public final Response sendChainCommand(
        byte ins, byte p1, byte p2, byte[] data) throws IOException
    {
        // выполнить команду
        return sendChainCommand(SecureType.NONE, null, ins, p1, p2, data); 
    }
    // выполнить команду
	public final Response sendChainCommand(int secureType, SecureClient secureClient, 
        byte ins, byte p1, byte p2, byte[] data) throws IOException
    {
        // для первых каналов
        byte cla; if (ordinal <= 3) cla = (byte)(ordinal | 0x10 | ((secureType & 0x3) << 2)); 
        
        else switch (secureType & 0x3)
        {
        // указать класс команды
        case SecureType.NONE         : cla = (byte)((ordinal - 4) | 0x50); break; 
        case SecureType.SECURE       : cla = (byte)((ordinal - 4) | 0x70); break;
        case SecureType.SECURE_HEADER: cla = (byte)((ordinal - 4) | 0x70); break; 
            
        // обработать возможную ошибку
        default: return new Response(new byte[0], (short)0x6A81); 
        }
        // при отсутствии защиты
        if (secureClient == null || secureType == SecureType.NONE || secureType == SecureType.PROPRIETARY)
        {
            // выполнить команду
            return environment().sendCommand(session(), cla, ins, p1, p2, data, 0); 
        }
        else {
            // указать криптографическую среду
            SecurityEnvironment securityEnvironment = SecurityEnvironment.CURRENT; 
            
            // получить параметры алгоритмов
            CRT.CT  cipherParameters = securityEnvironment.getCipherParameters(this); 
            CRT.CCT    macParameters = securityEnvironment.getMacParameters   (this); 
            CRT.DST   signParameters = securityEnvironment.getSignParameters  (this); 
            
            // выполнить защиту сообщения
            data = secureClient.protect(environment(), secureType, 
                cipherParameters, macParameters, signParameters, cla, ins, p1, p2, data, 0
            ); 
            // выполнить команду
            Response response = environment().sendCommand(session(), cla, ins, p1, p2, data, -1); 
            
            // снять защиту сообщения
            return secureClient.unprotect(environment(), 
                cipherParameters, macParameters, signParameters, response
            ); 
        }
    }
}

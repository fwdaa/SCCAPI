package aladdin.iso7816;
import aladdin.iso7816.ber.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Сеанс взаимодействия со смарт-картой
///////////////////////////////////////////////////////////////////////////
public abstract class CardSession extends LogicalChannel
{
    // клиент взаимодействия со смарт-картой и возможности смарт-карты
    private final CardClient client; private CardEnvironment environment;
    
    // конструктор
    protected CardSession() throws IOException { this(null); }
        
    // конструктор
    protected CardSession(CardClient client) throws IOException
    { 
        // сохранить переданные параметры
        this.client = client; environment = null;
    } 
    // возможности смарт-карты
    @Override public CardEnvironment environment() 
    { 
        // возможности смарт-карты
        return (environment != null) ? environment : atr().historicalBytes; 
    }
    // сеанс взаимодействия со смарт-картой
    @Override public CardSession session() { return this; }
    
    // клиент взаимодействия со смарт-картой
    public final CardClient client() { return client; }
    // ATR смарт-карты
    public abstract ATR atr();    
    
    // инициализировать сеанс
    protected void init(boolean afterReset) throws IOException 
    { 
        // проверить необходимость действий
        if (!afterReset) return; 
        
        // получить возможности смарт-карты
        if (client != null) { LifeCycle lifeCycle = environment().lifeCycle(); 
        
            // получить код состояния
            short sw = (lifeCycle != null) ? lifeCycle.SW : (short)0x9000; 
            
            // при запросе от карты
            if ((0x6202 <= sw && sw <= 0x6280) || (0x6402 <= sw && sw <= 0x6480)) 
            {
                // обработать запрос от карты
                Response response = client.reply(this, null, sw); 

                // проверить корректность выполнения
                ResponseException.check(response); 
            }
        }
        // получить описание команды описания возможностей
        InitialAccessData initialAccessData = environment().initialAccessData(); 
        
        // обработать файл EF.ATR
        if (initialAccessData == null) environment = environment().combineEFATR(this); 
        else {
            // выполнить команду
            Response response = environment().sendCommand(this, initialAccessData.command); 

            // проверить корректность выполнения
            ResponseException.check(response); 

            // раскодировать объекты
            DataObject[] objects = environment().dataCoding().decode(response.data, true); 

            // скорректировать описание возможностей смарт-карты
            environment = environment().combine(objects); 

            // обработать файл EF.ATR
            environment = environment.combineEFATR(this); 
        }
    } 
	// заблокировать/разблокировать смарт-карту
    public abstract void lock  () throws IOException; 
    public abstract void unlock() throws IOException; 
    
	// отправить команду смарт-карте
	public final Response sendCommand(byte cla, 
        byte ins, byte p1, byte p2, byte[] data, int ne) throws IOException
    {
        // отправить команду смарт-карте
        return environment().sendCommand(this, cla, ins, p1, p2, data, ne); 
    }
    // отправить команду смарт-карте
	public abstract byte[] sendCommand(byte... command) throws IOException; 
}

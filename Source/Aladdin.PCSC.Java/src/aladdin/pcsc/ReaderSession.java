package aladdin.pcsc; 
import aladdin.iso7816.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////
// Сеанс работы со считывателем
///////////////////////////////////////////////////////////////////////
public final class ReaderSession extends CardSession
{
	// модуль, описатель контекста и сеанса
	private final Module module; private final long hContext; private final long hSession; 

	// используемый протокол, ATR смарт-карты и необходимость закрытия
	private final int protocol; private final ATR atr; private final boolean dispose;

	// конструктор 
    public ReaderSession(Module module, ReaderScope scope, String readerName, 
        OpenMode openMode, int protocols, boolean afterReset) throws IOException
    {
        // указать предпочтительные протоколы
		this.module = module; int[] prefferedProtocols = new int[] { protocols }; 

	    // создать используемый контекст
	    hContext = module.establishContext(scope); dispose = true; 
        try { 
            // открыть считыватель
	        hSession = module.connect(hContext, readerName, openMode, prefferedProtocols);
            
            // получить ATR смарт-карты
            atr = new ATR(module.getReaderAttribute(hSession, API.SCARD_ATTR_ATR_STRING)); 

            // инициализировать сеанс
            protocol = prefferedProtocols[0]; init(afterReset); 
        }
        // освободить выделенные ресурсы
        catch (Throwable e) { module.releaseContext(hContext); throw e; }
    }
	// конструктор 
	public ReaderSession(Module module, long hContext, 
        long hSession, int protocol, byte[] atr) throws IOException
	{
		// сохранить переданные параметры
		this.module = module; this.hContext = hContext; this.hSession = hSession; 

        // сохранить переданные параметры
        this.protocol = protocol; this.atr = new ATR(atr); this.dispose = false;
	}
	// деструктор
	@Override protected void onClose() throws IOException
    { 
        // закрыть сеанс
        if (dispose) { module.disconnect(hSession, CloseMode.LEAVE); 
            
            // закрыть контекст
            module.releaseContext(hContext); 
        }
        super.onClose(); 
	}
    // ATR смарт-карты
    @Override public ATR atr() { return atr; }    
    
    // используемый протокол
    public int protocol() { return protocol; }

	// получить логические имена считывателя
	public String[] getReaderNames() throws IOException
    {
        // вернуть логические имена считывателя
        return module.getReaderStatus(hSession).readers; 
    }
    // получить атрибут считывателя/смарт-карты
    public byte[] getAttribute(int attrId) throws IOException
    {
        // получить атрибут считывателя/смарт-карты
        return module.getReaderAttribute(hSession, attrId); 
    }
    // ATR смарт-карты
    public byte[] getCardATR() throws IOException
    { 
        // ATR смарт-карты
        return getAttribute(API.SCARD_ATTR_ATR_STRING); 
    }
	// заблокировать смарт-карту
    @Override public void lock() throws IOException 
    { 
        // заблокировать смарт-карту
        module.beginTransaction(hSession); 
    } 
	// разблокировать смарт-карту
    @Override public void unlock() throws IOException 
    { 
        // разблокировать смарт-карту
        module.endTransaction(hSession, CloseMode.LEAVE); 
    }  
	// отправить команду считывателю
	public byte[] sendControl(int code, byte... data) throws IOException
    {
	    // отправить команду считывателю
        return module.sendControl(hSession, code, data, 32768); 
    }
	// отправить команду смарт-карте
	@Override public byte[] sendCommand(byte... encoded) throws IOException
    {
	    // отправить команду смарт-карте
        return module.sendCommand(hSession, protocol, encoded, 32768); 
    }
}

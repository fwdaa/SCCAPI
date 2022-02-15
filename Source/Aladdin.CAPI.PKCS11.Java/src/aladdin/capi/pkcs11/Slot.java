package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.pkcs11.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Считыватель для аппаратного криптографического устройства
///////////////////////////////////////////////////////////////////////////////
public class Slot extends RefObject implements aladdin.pcsc.IReader
{
	private final Provider	provider;   // используемый провайдер
    private final long      slotID;     // идентификатор считывателя
	private final String    name;		// имя считывателя

    // конструктор
	public Slot(Provider provider, long slotID) throws IOException
	{
        // сохранить переданные параметры
        this.provider = RefObject.addRef(provider); 
        
		// получить информацию о считывателе
		SlotInfo info = provider.module().getSlotInfo(slotID);  
        
        // сохранить имя считывателя
        this.slotID = slotID; this.name = info.slotDescription(); 
	}
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException  
    {
        // освободить выделенные ресурсы
        RefObject.release(provider); super.onClose();
    }
    // используемый провайдер
	public final Provider provider() { return provider; }
    
    // имя считывателя
	@Override public final String name() { return name; }

    // идентификатор считывателя
	public final long id() { return slotID; }
    
    // получить информацию считывателя
	public final SlotInfo getInfo() throws IOException
    { 
        // получить информацию считывателя
        return provider.module().getSlotInfo(slotID);	  
    }
    // состояние считывателя
    @Override public final aladdin.pcsc.ReaderState getState()
    {
        try { 
            // получить информацию считывателя
            SlotInfo info = getInfo(); 

            // при отсутствии устройства
            if ((info.flags() & API.CKF_TOKEN_PRESENT) == 0) 
            {
                // вернуть состояние считывателя
                return aladdin.pcsc.ReaderState.EMPTY; 
            }
            // вернуть состояние считывателя
            else return aladdin.pcsc.ReaderState.CARD; 
        }
        // обработать возможное исключение
        catch (IOException e) {} return aladdin.pcsc.ReaderState.UNAVAILABLE;
    }
	// смарт-карта считывателя
	@Override
	public final Token openCard() 
	{
        try {
            // получить информацию считывателя
            SlotInfo info = getInfo(); 

            // проверить наличие смарт-карты
            if ((info.flags() & API.CKF_TOKEN_PRESENT) == 0) return null;

            // вернуть объект смарт-карты
            else return new Token(this); 
        }
        // обработать возможное исключение
        catch (IOException e) {} return null; 
	}
};

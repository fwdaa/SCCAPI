package aladdin.capi.pkcs11;
import aladdin.*; 
import aladdin.capi.*;
import aladdin.pkcs11.*; 
import aladdin.pcsc.*; 
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Аппаратное устройство
///////////////////////////////////////////////////////////////////////////////
public class Token extends SecurityStore implements ICard
{
    // физический считыватель
	private final Slot slot;

	// конструктор
	public Token(Provider provider, long slotID) throws IOException
	{
        // сохранить переданные параметры
        super(provider, Scope.SYSTEM); 
        
        // сохранить переданные паераметры
        this.slot = new Slot(provider, slotID); 
    }
	// конструктор
	public Token(Slot slot) throws IOException
	{
        // сохранить переданные параметры
        super(slot.provider(), Scope.SYSTEM); 
        
        // сохранить переданные паераметры
        this.slot = RefObject.addRef(slot); 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException  
    {
        // освободить выделенные ресурсы
        RefObject.release(slot); super.onClose();
    }
	///////////////////////////////////////////////////////////////////////////
	// Атрибуты устройства
	///////////////////////////////////////////////////////////////////////////
	@Override public final Provider	provider() { return slot.provider(); }
    
    // имя смарт-карты
    @Override public String name() { return slot.name(); }
    
	// состояние смарт-карты
	@Override public CardState getState()
    { 
		// проверить состояние считывателя
		return (slot.getState() == ReaderState.CARD) ? CardState.PRESENT : CardState.EMPTY;
	}
	// описание считывателя
	@Override public final Slot reader() { return slot; }
    
	///////////////////////////////////////////////////////////////////////////
	// Управление объектами
	///////////////////////////////////////////////////////////////////////////
	@Override public String[] enumerateObjects() 
    {
        // создать список имен апплетов
        List<String> names = new ArrayList<String>(); 
        try {
            // получить список считывателей
            long[] slotList = provider().module().getSlotList(true); 

            // для всех найденных смарт-карт
            for (int i = 0; i < slotList.length; i++) 
            {
                // получить имя считывателя
                SlotInfo slotInfo = provider().module().getSlotInfo(slotList[i]); 

                // проверить совпадение имен
                if (!slotInfo.slotDescription().equals(slot.name())) continue; 
                
                // получить информацию устройства
                TokenInfo tokenInfo = provider().module().getTokenInfo(slotList[i]);	  
                
                // добавить имя апплета
                if (!names.contains(tokenInfo.model())) names.add(tokenInfo.model()); 
            }
        }
        // вернуть имена апплетов
        catch (Throwable e) {} return names.toArray(new String[names.size()]);
    }
	// открыть апплет
	@Override public SecurityObject openObject(Object name, String mode) throws IOException
    {
        // получить список считывателей
        long[] slotList = provider().module().getSlotList(true); 

        // для всех найденных смарт-карт
        for (int i = 0; i < slotList.length; i++) 
        {
            // получить имя считывателя
            SlotInfo slotInfo = provider().module().getSlotInfo(slotList[i]); 
            
            // проверить совпадение имен
            if (!slotInfo.slotDescription().equals(slot.name())) continue; 
            
            // получить информацию устройства
            TokenInfo tokenInfo = provider().module().getTokenInfo(slotList[i]);	  
            
            // проверить совпадение имени
            if (tokenInfo.model().equals(name.toString()))
            {
                // вернуть объект апплета
                return new Applet(this, slotList[i]); 
            }
        }
        // при ошибке выбросить исключение
        throw new NoSuchElementException(); 
    }
};

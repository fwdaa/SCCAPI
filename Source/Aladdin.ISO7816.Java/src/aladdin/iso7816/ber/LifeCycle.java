package aladdin.iso7816.ber;
import aladdin.iso7816.*; 

///////////////////////////////////////////////////////////////////////////
// Информация о состоянии (0x48)
///////////////////////////////////////////////////////////////////////////
public class LifeCycle extends DataObject
{
    public static final int UNKNOWN        = 0; // неизвестная фаза      
    public static final int CREATION       = 1; // фаза создания         
    public static final int INITIALISATION = 3; // фаза инициализации    
    public static final int DEACTIVATED    = 4; // неактивированная карта
    public static final int ACTIVATED      = 5; // активированная карта  
    public static final int TERMINATION    = 6; // уничтожаемая карта    
    
    // фаза жизненного цикла и код завершения
    public final int state; public final short SW;

    // конструктор
    public LifeCycle(Tag tag, int state, short sw) 
    {       
        // сохранить переданные параметры
        super(Authority.ISO7816, tag); 
        
        // сохранить переданные параметры
        this.state = state; this.SW = sw; 
    }
    // конструктор
    public LifeCycle(Tag tag, byte[] content) 
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, tag, content);
        
        // в зависимсоти от размера
        switch (content.length)
        {
        case 1: SW = (short)0x9000;
        
            // извлечь состояние карты
            state = content[0]; break; 
            
        case 2: 
            // указать код завершения
            SW = (short)((content[0] << 8) | content[1]); 
            
            // состояние неизвестно
            state = UNKNOWN; break; 
            
        case 3: 
            // извлечь состояние карты
            state = content[0]; 
               
            // указать код завершения
            SW = (short)((content[1] << 8) | content[2]); break; 
            
        default: 
            // состояние неизвестно
            state = UNKNOWN; SW = (short)0x9000; break; 
        }
    }
    // закодировать значение
    @Override public byte[] content() 
    {
        // закодировать объект
        return new byte[] { (byte)state, (byte)((SW >>> 8) & 0xFF), (byte)(SW & 0xFF) }; 
    }
}

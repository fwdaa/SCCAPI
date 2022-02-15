using System;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Информация о состоянии (0x48)
    ///////////////////////////////////////////////////////////////////////////
    public class LifeCycle : DataObject
    {
        public const int Unknown         = 0; // неизвестная фаза      
        public const int Creation        = 1; // фаза создания         
        public const int Initialisation  = 3; // фаза инициализации    
        public const int Deactivated     = 4; // неактивированная карта
        public const int Activated       = 5; // активированная карта  
        public const int Termination     = 6; // уничтожаемая карта    

        // фаза жизненного цикла и код завершения
        public readonly int State; public readonly ushort SW;

        // конструктор
        public LifeCycle(Tag tag, int state, ushort sw) 
            
            // сохранить переданные параметры
            : base(Authority.ISO7816, tag)
        {    
            // сохранить переданные параметры
            State = state; SW = sw; 
        }
        // конструктор
        public LifeCycle(Tag tag, byte[] content) : base(Authority.ISO7816, tag, content) 
        {
            // указать начальные условия
            State = Unknown; SW = 0x9000; switch (content.Length)
            {
            case 3: State = content[0]; 
                
                // указать код завершения
                SW = (ushort)((content[1] << 8) | content[2]); break; 
            case 2: 
                // указать код завершения
                SW = (ushort)((content[0] << 8) | content[1]); break; 

            case 1: State = content[0]; break; 
            }
        }
        // закодировать значение
        public override byte[] Content { get {
        
            // закодировать объект
            return new byte[] { (byte)State, (byte)(SW >> 8), (byte)SW }; 
        }}
    }
}

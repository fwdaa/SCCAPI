package aladdin.pcsc;

///////////////////////////////////////////////////////////////////////////
// Состояние смарт-карты
///////////////////////////////////////////////////////////////////////////
public enum CardState 
{ 
    EMPTY    (0), // отсутствует  в считывателе
    PRESENT  (1), // присутствует в считывателе
    MUTE     (3), // заблокированная карта
    EXCLUSIVE(5), // монопольный доступ другого процесса
    SHARED   (9); // разделяемый доступ с другими процессами
        
    // конструктор
    private CardState(int value) { intValue = value; } 
    
    // получить значение
    public int value() { return intValue; } private final int intValue;
}; 

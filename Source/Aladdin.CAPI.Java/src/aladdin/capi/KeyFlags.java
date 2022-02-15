package aladdin.capi;

///////////////////////////////////////////////////////////////////////////
// Дополнительные параметры ключа
///////////////////////////////////////////////////////////////////////////
public enum KeyFlags { NONE(0), EXPORTABLE(1); 

    // конструктор
    private KeyFlags(int value) { intValue = value; } 
    
    // получить значение
    public int value() { return intValue; } private final int intValue;

    // выполнить логическую операцию
    public static KeyFlags and(KeyFlags flags1, KeyFlags flags2)
    {
        // обработать отдельные случаи
        if (flags1 == KeyFlags.NONE) return KeyFlags.NONE; 
        if (flags2 == KeyFlags.NONE) return KeyFlags.NONE; 
        
        // обработать отдельные случаи
        return (flags1 == flags2) ? flags1 : KeyFlags.NONE; 
    }
    // выполнить логическую операцию
    public static KeyFlags or(KeyFlags flags1, KeyFlags flags2)
    {
        // обработать отдельные случаи
        if (flags1 == KeyFlags.NONE) return flags2; 
        if (flags2 == KeyFlags.NONE) return flags1; 
        
        // обработать отдельные случаи
        return (flags1 == flags2) ? flags1 : KeyFlags.EXPORTABLE; 
    }
}

package aladdin.iso7816;

///////////////////////////////////////////////////////////////////////////////
// Cпособ записи в файл
///////////////////////////////////////////////////////////////////////////////
public enum WriteType 
{ 
    PROPRIETARY  (0), // Proprietary
    WRITE_ERASED (1), // One-time write
    WRITE_OR     (2), // Write OR
    WRITE_AND    (3); // Write AND
        
    // конструктор
    private WriteType(int value) { intValue = value; } 
    
    // получить значение
    public int value() { return intValue; } private final int intValue;
}

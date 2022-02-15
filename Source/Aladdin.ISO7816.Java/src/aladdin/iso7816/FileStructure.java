package aladdin.iso7816;

///////////////////////////////////////////////////////////////////////////////
// Структура файла
///////////////////////////////////////////////////////////////////////////////
public enum FileStructure { 
    UNKNOWN                 ( 0), // No information given 
    TRANSPARENT             ( 1), // Transparent structure
    RECORD                  ( 2), // Record structure
    LINEAR_FIXED            ( 3), // Linear structure, fixed size, no further information
    LINEAR_FIXED_TLV        ( 4), // Linear structure, fixed size, TLV structure
    LINEAR_VARIABLE         ( 5), // Linear structure, variable size, no further information
    LINEAR_VARIABLE_TLV     ( 6), // Linear structure, variable size, TLV structure
    CYCLIC_FIXED            ( 7), // Cyclic structure, fixed size, no further information
    CYCLIC_FIXED_TLV        ( 8), // Cyclic structure, fixed size, TLV structure
    DATA_OBJECT             ( 9), // TLV structure 
    DATA_OBJECT_BERTLV      (10), // TLV structure for BER-TLV data objects
    DATA_OBJECT_SIMPLETLV   (11); // TLV structure for SIMPLE-TLV data objects 
        
    // конструктор
    private FileStructure(int value) { intValue = value; } 
    
    // получить значение
    public int value() { return intValue; } private final int intValue;
}

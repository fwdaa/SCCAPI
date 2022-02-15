using System;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Структура файла
    ///////////////////////////////////////////////////////////////////////////////
    public enum FileStructure { 
        Unknown              =  0, // No information given 
        Transparent          =  1, // Transparent structure
        Record               =  2, // Record structure
        LinearFixed          =  3, // Linear structure, fixed size, no further information
        LinearFixedTLV       =  4, // Linear structure, fixed size, TLV structure
        LinearVariable       =  5, // Linear structure, variable size, no further information
        LinearVariableTLV    =  6, // Linear structure, variable size, TLV structure
        CyclicFixed          =  7, // Cyclic structure, fixed size, no further information
        CyclicFixedTLV       =  8, // Cyclic structure, fixed size, TLV structure
        DataObject           =  9, // TLV structure
        DataObjectBERTLV     = 10, // TLV structure for BER-TLV data objects
        DataObjectSimpleTLV  = 11  // TLV structure for SIMPLE-TLV data objects 
    }
}

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Тип защиты сообщения
    ///////////////////////////////////////////////////////////////////////////////
    public enum SecureType 
    { 
        None         = 0x0, // No SM or no indication
        Proprietary  = 0x1, // Proprietary SM format
        Secure       = 0x2, // SM, command header not processed
        SecureHeader = 0x3, // SM, command header authenticated
        BERTLV       = 0x4, // SM, value encoded in BER-TLV
        BERTLVSM     = 0xC  // SM, value encoded in BER-TLV and including SM DOs
    }
}

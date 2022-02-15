package aladdin.iso7816;

///////////////////////////////////////////////////////////////////////////////
// Тип защиты сообщения
///////////////////////////////////////////////////////////////////////////////
public abstract class SecureType 
{ 
    public static final int NONE            = 0x0; // No SM or no indication
    public static final int PROPRIETARY     = 0x1; // Proprietary SM format
    public static final int SECURE          = 0x2; // SM, command header not processed
    public static final int SECURE_HEADER   = 0x3; // SM, command header authenticated
    public static final int BERTLV          = 0x4; // SM, value encoded in BER-TLV
    public static final int BERTLV_SM       = 0xC; // SM, value encoded in BER-TLV and including SM DOs
}

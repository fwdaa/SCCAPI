package aladdin.pcsc;

///////////////////////////////////////////////////////////////////////////////
// Тип протоколов
///////////////////////////////////////////////////////////////////////////////
public abstract class Protocol 
{ 
    public static final int UNKNOWN = 0; 
    public static final int RAW     = 1; 
    public static final int T0      = 2; 
    public static final int T1      = 4; 
    
    public static int encode(int protocols)
    {
        // инициализировать переменные
		int dwProtocols = API.SCARD_PROTOCOL_UNDEFINED; 

        // указать предпочтительные протоколы протокол
        if ((protocols & Protocol.RAW) != 0) dwProtocols |= API.SCARD_PROTOCOL_RAW; 
        if ((protocols & Protocol.T0 ) != 0) dwProtocols |= API.SCARD_PROTOCOL_T0; 
        if ((protocols & Protocol.T1 ) != 0) dwProtocols |= API.SCARD_PROTOCOL_T1; 

        return dwProtocols; 
    }
    public static int decode(int dwProtocols)
    {
        // сохранить переданные параметры
        int protocols = Protocol.UNKNOWN; 

        // определить используемый протокол
        if ((dwProtocols & API.SCARD_PROTOCOL_RAW) != 0) protocols |= Protocol.RAW; 
        if ((dwProtocols & API.SCARD_PROTOCOL_T0 ) != 0) protocols |= Protocol.T0; 
        if ((dwProtocols & API.SCARD_PROTOCOL_T1 ) != 0) protocols |= Protocol.T1; 
        
        return protocols; 
    }
}

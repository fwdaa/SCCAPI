using System;
using System.Runtime.InteropServices;

namespace Aladdin.PCSC
{
	///////////////////////////////////////////////////////////////////////
    // Исключение при работе со смарт-картами
	///////////////////////////////////////////////////////////////////////
    [Serializable]
	public class Exception : ExternalException
	{	
        // проверить код ошибки
        public static void Check(ulong code) 
        { 
            // проверить код ошибки
            if (code != API.SCARD_S_SUCCESS) throw new Exception(code); 
        }
        // конструктор
		public Exception(ulong code) : base(String.Empty, (int)code) {}

	    // сообщение об ошибке
	    public override String Message { get 
        {
		    switch ((uint)ErrorCode)
		    {
		    case API.SCARD_F_INTERNAL_ERROR		        : return "SCARD_F_INTERNAL_ERROR";
		    case API.SCARD_E_CANCELLED		            : return "SCARD_E_CANCELLED";
		    case API.SCARD_E_INVALID_HANDLE		        : return "SCARD_E_INVALID_HANDLE";
		    case API.SCARD_E_INVALID_PARAMETER	        : return "SCARD_E_INVALID_PARAMETER";
		    case API.SCARD_E_INVALID_TARGET		        : return "SCARD_E_INVALID_TARGET";
		    case API.SCARD_E_NO_MEMORY		            : return "SCARD_E_NO_MEMORY";
		    case API.SCARD_F_WAITED_TOO_LONG		    : return "SCARD_F_WAITED_TOO_LONG";
		    case API.SCARD_E_INSUFFICIENT_BUFFER	    : return "SCARD_E_INSUFFICIENT_BUFFER";
		    case API.SCARD_E_UNKNOWN_READER		        : return "SCARD_E_UNKNOWN_READER";
		    case API.SCARD_E_TIMEOUT			        : return "SCARD_E_TIMEOUT";
		    case API.SCARD_E_SHARING_VIOLATION	        : return "SCARD_E_SHARING_VIOLATION";
		    case API.SCARD_E_NO_SMARTCARD		        : return "SCARD_E_NO_SMARTCARD";
		    case API.SCARD_E_UNKNOWN_CARD		        : return "SCARD_E_UNKNOWN_CARD";
		    case API.SCARD_E_CANT_DISPOSE		        : return "SCARD_E_CANT_DISPOSE";
		    case API.SCARD_E_PROTO_MISMATCH		    	: return "SCARD_E_PROTO_MISMATCH";
		    case API.SCARD_E_NOT_READY		            : return "SCARD_E_NOT_READY";
		    case API.SCARD_E_INVALID_VALUE		        : return "SCARD_E_INVALID_VALUE";
		    case API.SCARD_E_SYSTEM_CANCELLED	        : return "SCARD_E_SYSTEM_CANCELLED";
		    case API.SCARD_F_COMM_ERROR		            : return "SCARD_F_COMM_ERROR";
		    case API.SCARD_F_UNKNOWN_ERROR		        : return "SCARD_F_UNKNOWN_ERROR";
		    case API.SCARD_E_INVALID_ATR		        : return "SCARD_E_INVALID_ATR";
		    case API.SCARD_E_NOT_TRANSACTED		        : return "SCARD_E_NOT_TRANSACTED";
		    case API.SCARD_E_READER_UNAVAILABLE	        : return "SCARD_E_READER_UNAVAILABLE";
		    case API.SCARD_P_SHUTDOWN		            : return "SCARD_P_SHUTDOWN";
		    case API.SCARD_E_PCI_TOO_SMALL		        : return "SCARD_E_PCI_TOO_SMALL";
		    case API.SCARD_E_READER_UNSUPPORTED	        : return "SCARD_E_READER_UNSUPPORTED";
		    case API.SCARD_E_DUPLICATE_READER	        : return "SCARD_E_DUPLICATE_READER";
		    case API.SCARD_E_CARD_UNSUPPORTED	        : return "SCARD_E_CARD_UNSUPPORTED";
		    case API.SCARD_E_NO_SERVICE		        	: return "SCARD_E_NO_SERVICE";
		    case API.SCARD_E_SERVICE_STOPPED		    : return "SCARD_E_SERVICE_STOPPED";
		    case API.SCARD_E_UNEXPECTED		        	: return "SCARD_E_UNEXPECTED";
		    case API.SCARD_E_UNSUPPORTED_FEATURE	    : return "SCARD_E_UNSUPPORTED_FEATURE";
		    case API.SCARD_E_ICC_INSTALLATION	        : return "SCARD_E_ICC_INSTALLATION";
		    case API.SCARD_E_ICC_CREATEORDER		    : return "SCARD_E_ICC_CREATEORDER";
		    case API.SCARD_E_DIR_NOT_FOUND		        : return "SCARD_E_DIR_NOT_FOUND";
		    case API.SCARD_E_FILE_NOT_FOUND		    	: return "SCARD_E_FILE_NOT_FOUND";
		    case API.SCARD_E_NO_DIR			            : return "SCARD_E_NO_DIR";
		    case API.SCARD_E_NO_FILE			        : return "SCARD_E_NO_FILE";
		    case API.SCARD_E_NO_ACCESS		            : return "SCARD_E_NO_ACCESS";
		    case API.SCARD_E_WRITE_TOO_MANY		        : return "SCARD_E_WRITE_TOO_MANY";
		    case API.SCARD_E_BAD_SEEK		            : return "SCARD_E_BAD_SEEK";
		    case API.SCARD_E_INVALID_CHV		        : return "SCARD_E_INVALID_CHV";
		    case API.SCARD_E_UNKNOWN_RES_MNG		    : return "SCARD_E_UNKNOWN_RES_MNG";
		    case API.SCARD_E_NO_SUCH_CERTIFICATE	    : return "SCARD_E_NO_SUCH_CERTIFICATE";
		    case API.SCARD_E_CERTIFICATE_UNAVAILABLE	: return "SCARD_E_CERTIFICATE_UNAVAILABLE";
		    case API.SCARD_E_NO_READERS_AVAILABLE       : return "SCARD_E_NO_READERS_AVAILABLE";
		    case API.SCARD_E_COMM_DATA_LOST		        : return "SCARD_E_COMM_DATA_LOST";
		    case API.SCARD_E_NO_KEY_CONTAINER	        : return "SCARD_E_NO_KEY_CONTAINER";
		    case API.SCARD_E_SERVER_TOO_BUSY		    : return "SCARD_E_SERVER_TOO_BUSY";
		    case API.SCARD_W_UNSUPPORTED_CARD	        : return "SCARD_W_UNSUPPORTED_CARD";
		    case API.SCARD_W_UNRESPONSIVE_CARD	        : return "SCARD_W_UNRESPONSIVE_CARD";
		    case API.SCARD_W_UNPOWERED_CARD		    	: return "SCARD_W_UNPOWERED_CARD";
		    case API.SCARD_W_RESET_CARD		            : return "SCARD_W_RESET_CARD";
		    case API.SCARD_W_REMOVED_CARD		        : return "SCARD_W_REMOVED_CARD";
		    case API.SCARD_W_SECURITY_VIOLATION	    	: return "SCARD_W_SECURITY_VIOLATION";
		    case API.SCARD_W_WRONG_CHV		            : return "SCARD_W_WRONG_CHV";
		    case API.SCARD_W_CHV_BLOCKED		        : return "SCARD_W_CHV_BLOCKED";
		    case API.SCARD_W_EOF			            : return "SCARD_W_EOF";
		    case API.SCARD_W_CANCELLED_BY_USER	        : return "SCARD_W_CANCELLED_BY_USER";
		    case API.SCARD_W_CARD_NOT_AUTHENTICATED	    : return "SCARD_W_CARD_NOT_AUTHENTICATED";
            }
		    // получить описание исключения
		    return String.Format("SCARD_0x{0:X8}", ErrorCode); 
	    }}
	}
}

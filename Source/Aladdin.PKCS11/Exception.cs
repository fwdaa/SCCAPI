using System;
using System.Runtime.Serialization;
using System.Runtime.InteropServices;

namespace Aladdin.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Исключение PKCS11
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class Exception : ExternalException
    {
        // проверить код ошибки
        public static void Check(ulong code) 
        { 
            // проверить код ошибки
            if (code != API.CKR_OK) throw new Exception(code); 
        }
	    // конструктор
	    public Exception(ulong code) : base(String.Empty, (int)code) {}

	    // сообщение об ошибке
	    public override String Message { get 
        {
		    switch ((uint)ErrorCode)
		    {
		    case API.CKR_OK								    : return "CKR_OK"; 
		    case API.CKR_CANCEL							    : return "CKR_CANCEL";				
		    case API.CKR_HOST_MEMORY						: return "CKR_HOST_MEMORY";
		    case API.CKR_SLOT_ID_INVALID					: return "CKR_SLOT_ID_INVALID";
		    case API.CKR_GENERAL_ERROR					    : return "CKR_GENERAL_ERROR";
		    case API.CKR_FUNCTION_FAILED					: return "CKR_FUNCTION_FAILED";
		    case API.CKR_ARGUMENTS_BAD					    : return "CKR_ARGUMENTS_BAD";
		    case API.CKR_NO_EVENT							: return "CKR_NO_EVENT";
		    case API.CKR_NEED_TO_CREATE_THREADS			    : return "CKR_NEED_TO_CREATE_THREADS";
		    case API.CKR_CANT_LOCK						    : return "CKR_CANT_LOCK";
		    case API.CKR_ATTRIBUTE_READ_ONLY				: return "CKR_ATTRIBUTE_READ_ONLY";	
		    case API.CKR_ATTRIBUTE_SENSITIVE				: return "CKR_ATTRIBUTE_SENSITIVE";
		    case API.CKR_ATTRIBUTE_TYPE_INVALID			    : return "CKR_ATTRIBUTE_TYPE_INVALID";
		    case API.CKR_ATTRIBUTE_VALUE_INVALID			: return "CKR_ATTRIBUTE_VALUE_INVALID";
		    case API.CKR_DATA_INVALID						: return "CKR_DATA_INVALID";
		    case API.CKR_DATA_LEN_RANGE					    : return "CKR_DATA_LEN_RANGE";
		    case API.CKR_DEVICE_ERROR						: return "CKR_DEVICE_ERROR";
		    case API.CKR_DEVICE_MEMORY					    : return "CKR_DEVICE_MEMORY";
		    case API.CKR_DEVICE_REMOVED					    : return "CKR_DEVICE_REMOVED";
		    case API.CKR_ENCRYPTED_DATA_INVALID			    : return "CKR_ENCRYPTED_DATA_INVALID";
		    case API.CKR_ENCRYPTED_DATA_LEN_RANGE			: return "CKR_ENCRYPTED_DATA_LEN_RANGE";
		    case API.CKR_FUNCTION_CANCELED				    : return "CKR_FUNCTION_CANCELED";
		    case API.CKR_FUNCTION_NOT_PARALLEL			    : return "CKR_FUNCTION_NOT_PARALLEL";
		    case API.CKR_FUNCTION_NOT_SUPPORTED			    : return "CKR_FUNCTION_NOT_SUPPORTED"; 
		    case API.CKR_KEY_HANDLE_INVALID				    : return "CKR_KEY_HANDLE_INVALID";
		    case API.CKR_KEY_SIZE_RANGE					    : return "CKR_KEY_SIZE_RANGE";
		    case API.CKR_KEY_TYPE_INCONSISTENT			    : return "CKR_KEY_TYPE_INCONSISTENT";
		    case API.CKR_KEY_NOT_NEEDED					    : return "CKR_KEY_NOT_NEEDED";
		    case API.CKR_KEY_CHANGED						: return "CKR_KEY_CHANGED";
		    case API.CKR_KEY_NEEDED						    : return "CKR_KEY_NEEDED";
		    case API.CKR_KEY_INDIGESTIBLE					: return "CKR_KEY_INDIGESTIBLE";
		    case API.CKR_KEY_FUNCTION_NOT_PERMITTED		    : return "CKR_KEY_FUNCTION_NOT_PERMITTED";
		    case API.CKR_KEY_NOT_WRAPPABLE				    : return "CKR_KEY_NOT_WRAPPABLE";
		    case API.CKR_KEY_UNEXTRACTABLE				    : return "CKR_KEY_UNEXTRACTABLE";
		    case API.CKR_MECHANISM_INVALID				    : return "CKR_MECHANISM_INVALID";
		    case API.CKR_MECHANISM_PARAM_INVALID			: return "CKR_MECHANISM_PARAM_INVALID";
		    case API.CKR_OBJECT_HANDLE_INVALID			    : return "CKR_OBJECT_HANDLE_INVALID";
		    case API.CKR_OPERATION_ACTIVE					: return "CKR_OPERATION_ACTIVE";
		    case API.CKR_OPERATION_NOT_INITIALIZED		    : return "CKR_OPERATION_NOT_INITIALIZED";
		    case API.CKR_PIN_INCORRECT					    : return "CKR_PIN_INCORRECT";
		    case API.CKR_PIN_INVALID						: return "CKR_PIN_INVALID";
		    case API.CKR_PIN_LEN_RANGE					    : return "CKR_PIN_LEN_RANGE";
		    case API.CKR_PIN_EXPIRED						: return "CKR_PIN_EXPIRED";
		    case API.CKR_PIN_LOCKED						    : return "CKR_PIN_LOCKED";
		    case API.CKR_SESSION_CLOSED					    : return "CKR_SESSION_CLOSED";
		    case API.CKR_SESSION_COUNT					    : return "CKR_SESSION_COUNT";
		    case API.CKR_SESSION_HANDLE_INVALID			    : return "CKR_SESSION_HANDLE_INVALID";
		    case API.CKR_SESSION_PARALLEL_NOT_SUPPORTED	    : return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
		    case API.CKR_SESSION_READ_ONLY				    : return "CKR_SESSION_READ_ONLY";
		    case API.CKR_SESSION_EXISTS					    : return "CKR_SESSION_EXISTS";
		    case API.CKR_SESSION_READ_ONLY_EXISTS			: return "CKR_SESSION_READ_ONLY_EXISTS";
		    case API.CKR_SESSION_READ_WRITE_SO_EXISTS		: return "CKR_SESSION_READ_WRITE_SO_EXISTS";
		    case API.CKR_SIGNATURE_INVALID				    : return "CKR_SIGNATURE_INVALID";
		    case API.CKR_SIGNATURE_LEN_RANGE				: return "CKR_SIGNATURE_LEN_RANGE";
		    case API.CKR_TEMPLATE_INCOMPLETE				: return "CKR_TEMPLATE_INCOMPLETE";
		    case API.CKR_TEMPLATE_INCONSISTENT			    : return "CKR_TEMPLATE_INCONSISTENT";
		    case API.CKR_TOKEN_NOT_PRESENT				    : return "CKR_TOKEN_NOT_PRESENT";
		    case API.CKR_TOKEN_NOT_RECOGNIZED				: return "CKR_TOKEN_NOT_RECOGNIZED";
		    case API.CKR_TOKEN_WRITE_PROTECTED			    : return "CKR_TOKEN_WRITE_PROTECTED";
		    case API.CKR_UNWRAPPING_KEY_HANDLE_INVALID	    : return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
		    case API.CKR_UNWRAPPING_KEY_SIZE_RANGE		    : return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
		    case API.CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT	: return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
		    case API.CKR_USER_ALREADY_LOGGED_IN			    : return "CKR_USER_ALREADY_LOGGED_IN";
		    case API.CKR_USER_NOT_LOGGED_IN				    : return "CKR_USER_NOT_LOGGED_IN";
		    case API.CKR_USER_PIN_NOT_INITIALIZED			: return "CKR_USER_PIN_NOT_INITIALIZED";
		    case API.CKR_USER_TYPE_INVALID				    : return "CKR_USER_TYPE_INVALID";
		    case API.CKR_USER_ANOTHER_ALREADY_LOGGED_IN	    : return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
		    case API.CKR_USER_TOO_MANY_TYPES				: return "CKR_USER_TOO_MANY_TYPES";
		    case API.CKR_WRAPPED_KEY_INVALID				: return "CKR_WRAPPED_KEY_INVALID";
		    case API.CKR_WRAPPED_KEY_LEN_RANGE			    : return "CKR_WRAPPED_KEY_LEN_RANGE";
		    case API.CKR_WRAPPING_KEY_HANDLE_INVALID		: return "CKR_WRAPPING_KEY_HANDLE_INVALID";
		    case API.CKR_WRAPPING_KEY_SIZE_RANGE			: return "CKR_WRAPPING_KEY_SIZE_RANGE";
		    case API.CKR_WRAPPING_KEY_TYPE_INCONSISTENT	    : return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
		    case API.CKR_RANDOM_SEED_NOT_SUPPORTED		    : return "CKR_RANDOM_SEED_NOT_SUPPORTED";
		    case API.CKR_RANDOM_NO_RNG					    : return "CKR_RANDOM_NO_RNG";
		    case API.CKR_BUFFER_TOO_SMALL					: return "CKR_BUFFER_TOO_SMALL";
		    case API.CKR_SAVED_STATE_INVALID				: return "CKR_SAVED_STATE_INVALID";
		    case API.CKR_INFORMATION_SENSITIVE			    : return "CKR_INFORMATION_SENSITIVE";
		    case API.CKR_STATE_UNSAVEABLE					: return "CKR_STATE_UNSAVEABLE";
		    case API.CKR_CRYPTOKI_NOT_INITIALIZED			: return "CKR_CRYPTOKI_NOT_INITIALIZED";
		    case API.CKR_CRYPTOKI_ALREADY_INITIALIZED		: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
		    case API.CKR_MUTEX_BAD						    : return "CKR_MUTEX_BAD";
		    case API.CKR_MUTEX_NOT_LOCKED					: return "CKR_MUTEX_NOT_LOCKED";
		    case API.CKR_VENDOR_DEFINED					    : return "CKR_VENDOR_DEFINED";
		    }
		    // получить описание исключения
		    return String.Format("CKR_0x{0:X8}", ErrorCode); 
	    }}
    }
}

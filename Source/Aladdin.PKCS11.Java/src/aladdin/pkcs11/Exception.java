package aladdin.pkcs11;
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Исключение PKCS#11
///////////////////////////////////////////////////////////////////////////////
public class Exception extends IOException
{
    // номер версии для сериализации
    private static final long serialVersionUID = 6853106839840797634L;

    private static final Map<Long, String> errors = new HashMap<Long, String>();
    static {
        errors.put(API.CKR_OK								, "CKR_OK"								);
        errors.put(API.CKR_CANCEL							, "CKR_CANCEL"							);
        errors.put(API.CKR_HOST_MEMORY						, "CKR_HOST_MEMORY"						);
        errors.put(API.CKR_SLOT_ID_INVALID					, "CKR_SLOT_ID_INVALID"					);
        errors.put(API.CKR_GENERAL_ERROR                    , "CKR_GENERAL_ERROR"					);
        errors.put(API.CKR_FUNCTION_FAILED					, "CKR_FUNCTION_FAILED"					);
        errors.put(API.CKR_ARGUMENTS_BAD                    , "CKR_ARGUMENTS_BAD"					);
        errors.put(API.CKR_NO_EVENT							, "CKR_NO_EVENT"						);
        errors.put(API.CKR_NEED_TO_CREATE_THREADS			, "CKR_NEED_TO_CREATE_THREADS"			);
        errors.put(API.CKR_CANT_LOCK                        , "CKR_CANT_LOCK"						);
        errors.put(API.CKR_ATTRIBUTE_READ_ONLY				, "CKR_ATTRIBUTE_READ_ONLY"				);
        errors.put(API.CKR_ATTRIBUTE_SENSITIVE				, "CKR_ATTRIBUTE_SENSITIVE"				);
        errors.put(API.CKR_ATTRIBUTE_TYPE_INVALID			, "CKR_ATTRIBUTE_TYPE_INVALID"			);
        errors.put(API.CKR_ATTRIBUTE_VALUE_INVALID			, "CKR_ATTRIBUTE_VALUE_INVALID"			);
        errors.put(API.CKR_DATA_INVALID						, "CKR_DATA_INVALID"					);
        errors.put(API.CKR_DATA_LEN_RANGE					, "CKR_DATA_LEN_RANGE"					);
        errors.put(API.CKR_DEVICE_ERROR						, "CKR_DEVICE_ERROR"					);
        errors.put(API.CKR_DEVICE_MEMORY                    , "CKR_DEVICE_MEMORY"					);
        errors.put(API.CKR_DEVICE_REMOVED					, "CKR_DEVICE_REMOVED"					);
        errors.put(API.CKR_ENCRYPTED_DATA_INVALID			, "CKR_ENCRYPTED_DATA_INVALID"			);
        errors.put(API.CKR_ENCRYPTED_DATA_LEN_RANGE			, "CKR_ENCRYPTED_DATA_LEN_RANGE"		);
        errors.put(API.CKR_FUNCTION_CANCELED                , "CKR_FUNCTION_CANCELED"				);
        errors.put(API.CKR_FUNCTION_NOT_PARALLEL            , "CKR_FUNCTION_NOT_PARALLEL"			);
        errors.put(API.CKR_FUNCTION_NOT_SUPPORTED			, "CKR_FUNCTION_NOT_SUPPORTED"			);
        errors.put(API.CKR_KEY_HANDLE_INVALID				, "CKR_KEY_HANDLE_INVALID"				);
        errors.put(API.CKR_KEY_SIZE_RANGE					, "CKR_KEY_SIZE_RANGE"					);
        errors.put(API.CKR_KEY_TYPE_INCONSISTENT            , "CKR_KEY_TYPE_INCONSISTENT"			);
        errors.put(API.CKR_KEY_NOT_NEEDED					, "CKR_KEY_NOT_NEEDED"					);
        errors.put(API.CKR_KEY_CHANGED						, "CKR_KEY_CHANGED"						);
        errors.put(API.CKR_KEY_NEEDED						, "CKR_KEY_NEEDED"						);
        errors.put(API.CKR_KEY_INDIGESTIBLE					, "CKR_KEY_INDIGESTIBLE"				);
        errors.put(API.CKR_KEY_FUNCTION_NOT_PERMITTED		, "CKR_KEY_FUNCTION_NOT_PERMITTED"		);
        errors.put(API.CKR_KEY_NOT_WRAPPABLE                , "CKR_KEY_NOT_WRAPPABLE"				);
        errors.put(API.CKR_KEY_UNEXTRACTABLE                , "CKR_KEY_UNEXTRACTABLE"				);
        errors.put(API.CKR_MECHANISM_INVALID                , "CKR_MECHANISM_INVALID"				);
        errors.put(API.CKR_MECHANISM_PARAM_INVALID			, "CKR_MECHANISM_PARAM_INVALID"			);
        errors.put(API.CKR_OBJECT_HANDLE_INVALID            , "CKR_OBJECT_HANDLE_INVALID"			);
        errors.put(API.CKR_OPERATION_ACTIVE					, "CKR_OPERATION_ACTIVE"				);
        errors.put(API.CKR_OPERATION_NOT_INITIALIZED        , "CKR_OPERATION_NOT_INITIALIZED"		);
        errors.put(API.CKR_PIN_INCORRECT                    , "CKR_PIN_INCORRECT"					);
        errors.put(API.CKR_PIN_INVALID						, "CKR_PIN_INVALID"						);
        errors.put(API.CKR_PIN_LEN_RANGE                    , "CKR_PIN_LEN_RANGE"					);
        errors.put(API.CKR_PIN_EXPIRED						, "CKR_PIN_EXPIRED"						);
        errors.put(API.CKR_PIN_LOCKED						, "CKR_PIN_LOCKED"						);
        errors.put(API.CKR_SESSION_CLOSED					, "CKR_SESSION_CLOSED"					);
        errors.put(API.CKR_SESSION_COUNT                    , "CKR_SESSION_COUNT"					);
        errors.put(API.CKR_SESSION_HANDLE_INVALID			, "CKR_SESSION_HANDLE_INVALID"			);
        errors.put(API.CKR_SESSION_PARALLEL_NOT_SUPPORTED	, "CKR_SESSION_PARALLEL_NOT_SUPPORTED"	);
        errors.put(API.CKR_SESSION_READ_ONLY                , "CKR_SESSION_READ_ONLY"				);
        errors.put(API.CKR_SESSION_EXISTS					, "CKR_SESSION_EXISTS"					);
        errors.put(API.CKR_SESSION_READ_ONLY_EXISTS			, "CKR_SESSION_READ_ONLY_EXISTS"		);
        errors.put(API.CKR_SESSION_READ_WRITE_SO_EXISTS		, "CKR_SESSION_READ_WRITE_SO_EXISTS"	);
        errors.put(API.CKR_SIGNATURE_INVALID                , "CKR_SIGNATURE_INVALID"				);
        errors.put(API.CKR_SIGNATURE_LEN_RANGE				, "CKR_SIGNATURE_LEN_RANGE"				);
        errors.put(API.CKR_TEMPLATE_INCOMPLETE				, "CKR_TEMPLATE_INCOMPLETE"				);
        errors.put(API.CKR_TEMPLATE_INCONSISTENT            , "CKR_TEMPLATE_INCONSISTENT"			);
        errors.put(API.CKR_TOKEN_NOT_PRESENT                , "CKR_TOKEN_NOT_PRESENT"				);
        errors.put(API.CKR_TOKEN_NOT_RECOGNIZED				, "CKR_TOKEN_NOT_RECOGNIZED"			);
        errors.put(API.CKR_TOKEN_WRITE_PROTECTED            , "CKR_TOKEN_WRITE_PROTECTED"			);
        errors.put(API.CKR_UNWRAPPING_KEY_HANDLE_INVALID    , "CKR_UNWRAPPING_KEY_HANDLE_INVALID"	);
        errors.put(API.CKR_UNWRAPPING_KEY_SIZE_RANGE        , "CKR_UNWRAPPING_KEY_SIZE_RANGE"		);
        errors.put(API.CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT , "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT");
        errors.put(API.CKR_USER_ALREADY_LOGGED_IN			, "CKR_USER_ALREADY_LOGGED_IN"			);
        errors.put(API.CKR_USER_NOT_LOGGED_IN				, "CKR_USER_NOT_LOGGED_IN"				);
        errors.put(API.CKR_USER_PIN_NOT_INITIALIZED			, "CKR_USER_PIN_NOT_INITIALIZED"		);
        errors.put(API.CKR_USER_TYPE_INVALID                , "CKR_USER_TYPE_INVALID"				);
        errors.put(API.CKR_USER_ANOTHER_ALREADY_LOGGED_IN	, "CKR_USER_ANOTHER_ALREADY_LOGGED_IN"	);
        errors.put(API.CKR_USER_TOO_MANY_TYPES				, "CKR_USER_TOO_MANY_TYPES"				);
        errors.put(API.CKR_WRAPPED_KEY_INVALID				, "CKR_WRAPPED_KEY_INVALID"				);
        errors.put(API.CKR_WRAPPED_KEY_LEN_RANGE            , "CKR_WRAPPED_KEY_LEN_RANGE"			);
        errors.put(API.CKR_WRAPPING_KEY_HANDLE_INVALID		, "CKR_WRAPPING_KEY_HANDLE_INVALID"		);
        errors.put(API.CKR_WRAPPING_KEY_SIZE_RANGE			, "CKR_WRAPPING_KEY_SIZE_RANGE"			);
        errors.put(API.CKR_WRAPPING_KEY_TYPE_INCONSISTENT	, "CKR_WRAPPING_KEY_TYPE_INCONSISTENT"	);
        errors.put(API.CKR_RANDOM_SEED_NOT_SUPPORTED        , "CKR_RANDOM_SEED_NOT_SUPPORTED"		);
        errors.put(API.CKR_RANDOM_NO_RNG                    , "CKR_RANDOM_NO_RNG"					);
        errors.put(API.CKR_DOMAIN_PARAMS_INVALID            , "CKR_DOMAIN_PARAMS_INVALID"           );
        errors.put(API.CKR_BUFFER_TOO_SMALL					, "CKR_BUFFER_TOO_SMALL"				);
        errors.put(API.CKR_SAVED_STATE_INVALID				, "CKR_SAVED_STATE_INVALID"				);
        errors.put(API.CKR_INFORMATION_SENSITIVE            , "CKR_INFORMATION_SENSITIVE"			);
        errors.put(API.CKR_STATE_UNSAVEABLE					, "CKR_STATE_UNSAVEABLE"				);
        errors.put(API.CKR_CRYPTOKI_NOT_INITIALIZED			, "CKR_CRYPTOKI_NOT_INITIALIZED"		);
        errors.put(API.CKR_CRYPTOKI_ALREADY_INITIALIZED		, "CKR_CRYPTOKI_ALREADY_INITIALIZED"	);
        errors.put(API.CKR_MUTEX_BAD                        , "CKR_MUTEX_BAD"						);
        errors.put(API.CKR_MUTEX_NOT_LOCKED					, "CKR_MUTEX_NOT_LOCKED"				);
        errors.put(API.CKR_VENDOR_DEFINED					, "CKR_VENDOR_DEFINED"					);
    }
    // Constructor taking the error code as defined for the CKR_* constants
    // in PKCS#11.
    public Exception(long errorCode) { code = errorCode; } protected long code;

    // This method gets the corresponding text error message from
    // a property file. If this file is not available, it returns the error
    // code as a hex-string.
    // @return The message or the error code; e.g. "CKR_DEVICE_ERROR" or
    // "0x00000030".
    @Override
    public String getMessage()
    {
        String message = errors.get(Long.valueOf(code));

        if (message != null) return message;

        return String.format("CKR_0x%1$08X", (int)code); 
    }
    // Returns the PKCS#11 error code.
    // @return The error code; e.g. 0x00000030.
    public long getErrorCode() { return code; }
}

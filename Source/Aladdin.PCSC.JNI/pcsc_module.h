#pragma once

///////////////////////////////////////////////////////////////////////////////
// Прототипы функций
///////////////////////////////////////////////////////////////////////////////
#ifdef WIN32
#define SCARDAPI WINAPI
#else 
#define SCARDAPI 
#endif 

typedef LONG (SCARDAPI* SCARD_ESTABLISH_CONTEXT)(
	DWORD, LPCVOID, LPCVOID, LPSCARDCONTEXT
);
typedef LONG (SCARDAPI* SCARD_RELEASE_CONTEXT)(SCARDCONTEXT);
typedef LONG (SCARDAPI* SCARD_FREE_MEMORY)(
    SCARDCONTEXT, LPCVOID
);
typedef LONG (SCARDAPI* SCARD_LIST_READER_GROUPS_A)(
    SCARDCONTEXT, LPSTR, LPDWORD
);
typedef LONG (SCARDAPI* SCARD_LIST_READER_GROUPS_W)(
    SCARDCONTEXT, LPWSTR, LPDWORD
);
typedef LONG (SCARDAPI* SCARD_LIST_READERS_A)(
    SCARDCONTEXT, LPCSTR, LPSTR, LPDWORD
);
typedef LONG (SCARDAPI* SCARD_LIST_READERS_W)(
    SCARDCONTEXT, LPCWSTR, LPWSTR, LPDWORD
);
typedef LONG (SCARDAPI* SCARD_GET_STATUS_CHANGE_A)(
    SCARDCONTEXT, DWORD, LPSCARD_READERSTATEA, DWORD
);
typedef LONG (SCARDAPI* SCARD_GET_STATUS_CHANGE_W)(
    SCARDCONTEXT, DWORD, LPSCARD_READERSTATEW, DWORD
);
typedef LONG (SCARDAPI* SCARD_CANCEL)(SCARDCONTEXT);
typedef LONG (SCARDAPI* SCARD_CONNECT_A)(
    SCARDCONTEXT, LPCSTR, DWORD, DWORD, LPSCARDHANDLE, LPDWORD
);
typedef LONG (SCARDAPI* SCARD_CONNECT_W)(
    SCARDCONTEXT, LPCWSTR, DWORD, DWORD, LPSCARDHANDLE, LPDWORD
);
typedef LONG (SCARDAPI* SCARD_RECONNECT)(
    SCARDHANDLE, DWORD, DWORD, DWORD, LPDWORD
);
typedef LONG (SCARDAPI* SCARD_DISCONNECT)(
    SCARDHANDLE, DWORD
);
typedef LONG (SCARDAPI* SCARD_STATUS_A)(
    SCARDHANDLE, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD
);
typedef LONG (SCARDAPI* SCARD_STATUS_W)(
    SCARDHANDLE, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD
);
typedef LONG (SCARDAPI* SCARD_GET_ATTRIB)(
    SCARDHANDLE, DWORD, LPBYTE, LPDWORD
);
typedef LONG (SCARDAPI* SCARD_SET_ATTRIB)(
    SCARDHANDLE, DWORD, LPCBYTE, DWORD
);
typedef LONG (SCARDAPI* SCARD_BEGIN_TRANSACTION)(SCARDHANDLE);
typedef LONG (SCARDAPI* SCARD_END_TRANSACTION)(
    SCARDHANDLE, DWORD
);
typedef LONG (SCARDAPI* SCARD_CONTROL)(
    SCARDHANDLE, DWORD, LPCVOID, DWORD, LPVOID, DWORD, LPDWORD
);
typedef LONG (SCARDAPI* SCARD_TRANSMIT)(
    SCARDHANDLE, LPCSCARD_IO_REQUEST, LPCBYTE, DWORD, 
	LPSCARD_IO_REQUEST, LPBYTE, LPDWORD
);
///////////////////////////////////////////////////////////////////////////////
// Список функций PC/SC
///////////////////////////////////////////////////////////////////////////////
typedef struct SCARD_FUNCTION_LIST {
	SCARD_ESTABLISH_CONTEXT		scardEstablishContext; 
	SCARD_RELEASE_CONTEXT		scardReleaseContext; 
	SCARD_FREE_MEMORY			scardFreeMemory; 
	SCARD_LIST_READER_GROUPS_A	scardListReaderGroupsA; 
	SCARD_LIST_READER_GROUPS_W	scardListReaderGroupsW; 
	SCARD_LIST_READERS_A		scardListReadersA; 
	SCARD_LIST_READERS_W		scardListReadersW; 
	SCARD_GET_STATUS_CHANGE_A	scardGetStatusChangeA; 
	SCARD_GET_STATUS_CHANGE_W	scardGetStatusChangeW;
	SCARD_CANCEL				scardCancel;
	SCARD_CONNECT_A				scardConnectA;
	SCARD_CONNECT_W				scardConnectW;
	SCARD_RECONNECT				scardReconnect;
	SCARD_DISCONNECT			scardDisconnect;
	SCARD_STATUS_A				scardStatusA;
	SCARD_STATUS_W				scardStatusW;
	SCARD_GET_ATTRIB			scardGetAttrib;
	SCARD_SET_ATTRIB			scardSetAttrib;
	SCARD_BEGIN_TRANSACTION		scardBeginTransaction;
	SCARD_END_TRANSACTION		scardEndTransaction;
	SCARD_CONTROL				scardControl;
	SCARD_TRANSMIT				scardTransmit;
} SCARD_FUNCTION_LIST, *SCARD_FUNCTION_LIST_PTR;

namespace Aladdin { namespace PCSC {

///////////////////////////////////////////////////////////////////////////////
// Глобальные данные модуля PKCS#11
///////////////////////////////////////////////////////////////////////////////
class ModuleEntry
{
	// используемая Java-машина, версия JNI
	private: JavaVM* jvm; private: jint	version; 
	// список функций PC/SC
	private: SCARD_FUNCTION_LIST functionList;

	// конструктор/деструктор
	public: ModuleEntry(JNIEnv*); public: ~ModuleEntry();

	// используемая Java-машина и версия интерфейса JNI
	public: JavaVM* JVM    () const { return jvm;     }
	public: jint    Version() const { return version; }

	// список функций PKCS#11
	public: const SCARD_FUNCTION_LIST* FunctionList() const { return &functionList; }
};

}}

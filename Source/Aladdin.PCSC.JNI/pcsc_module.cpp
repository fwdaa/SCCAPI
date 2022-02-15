#include "stdafx.h"
#include "pcsc_wrapper.h"

///////////////////////////////////////////////////////////////////////////////
// �������� ������ � �� Windows
///////////////////////////////////////////////////////////////////////////////
#ifdef WIN32
Aladdin::PCSC::ModuleEntry::ModuleEntry(JNIEnv* env)
{
	// �������� ������� Java-������
	JNI_CHECK(env, env->GetJavaVM(&jvm)); this->version = env->GetVersion();

	// ��������� ������ �������
	functionList.scardEstablishContext	= &SCardEstablishContext;	
	functionList.scardReleaseContext 	= &SCardReleaseContext; 
	functionList.scardFreeMemory 		= &SCardFreeMemory; 
	functionList.scardListReaderGroupsA = &SCardListReaderGroupsA;
	functionList.scardListReaderGroupsW = &SCardListReaderGroupsW;
	functionList.scardListReadersA 		= &SCardListReadersA; 
	functionList.scardListReadersW 		= &SCardListReadersW; 
	functionList.scardGetStatusChangeA  = &SCardGetStatusChangeA;
	functionList.scardGetStatusChangeW	= &SCardGetStatusChangeW;
	functionList.scardCancel			= &SCardCancel;
	functionList.scardConnectA			= &SCardConnectA;
	functionList.scardConnectW			= &SCardConnectW;
	functionList.scardReconnect			= &SCardReconnect;
	functionList.scardDisconnect		= &SCardDisconnect;
	functionList.scardStatusA			= &SCardStatusA;
	functionList.scardStatusW			= &SCardStatusW;
	functionList.scardGetAttrib			= &SCardGetAttrib;
	functionList.scardSetAttrib			= &SCardSetAttrib;
	functionList.scardBeginTransaction	= &SCardBeginTransaction;
	functionList.scardEndTransaction	= &SCardEndTransaction;
	functionList.scardControl			= &SCardControl;
	functionList.scardTransmit			= &SCardTransmit;
}

Aladdin::PCSC::ModuleEntry::~ModuleEntry() {} 

#else 
///////////////////////////////////////////////////////////////////////////////
// �������� ������ � �� Linux
///////////////////////////////////////////////////////////////////////////////
Aladdin::PKCS11::ModuleEntry::ModuleEntry(JNIEnv* env)
{
	// �������� ������� Java-������
	JNI_CHECK(env, env->GetJavaVM(&jvm)); this->version = env->GetVersion();

	// ��������� ������ �������
	functionList.scardEstablishContext	= &SCardEstablishContext;	
	functionList.scardReleaseContext 	= &SCardReleaseContext; 
	functionList.scardFreeMemory 		= &SCardFreeMemory; 
	functionList.scardListReaderGroupsA = &SCardListReaderGroups;
	functionList.scardListReadersA 		= &SCardListReaders; 
	functionList.scardGetStatusChangeA  = &SCardGetStatusChange;
	functionList.scardCancel			= &SCardCancel;
	functionList.scardConnectA			= &SCardConnect;
	functionList.scardReconnect			= &SCardReconnect;
	functionList.scardDisconnect		= &SCardDisconnect;
	functionList.scardStatusA			= &SCardStatus;
	functionList.scardGetAttrib			= &SCardGetAttrib;
	functionList.scardSetAttrib			= &SCardSetAttrib;
	functionList.scardBeginTransaction	= &SCardBeginTransaction;
	functionList.scardEndTransaction	= &SCardEndTransaction;
	functionList.scardControl			= &SCardControl;
	functionList.scardTransmit			= &SCardTransmit;

	// ������� ���������������� �������
	functionList.scardListReaderGroupsW = NULL;
	functionList.scardListReadersW 		= NULL; 
	functionList.scardGetStatusChangeW	= NULL;
	functionList.scardConnectW			= NULL;
	functionList.scardStatusW			= NULL;
}

Aladdin::PKCS11::ModuleEntry::~ModuleEntry() {} 
#endif 


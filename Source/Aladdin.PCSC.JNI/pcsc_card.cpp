#include "stdafx.h"
#include "pcsc_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PCSC; 

///////////////////////////////////////////////////////////////////////////////
// ���������� ������������� � �����-�������
///////////////////////////////////////////////////////////////////////////////
extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pcsc_Wrapper_connect(
	JNIEnv* env, jobject jModule, jlong jContext, 
	jstring jReader, jint jShareMode, jintArray jProtocols)
try {
	// �������� ������ �������
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	SCARDCONTEXT hContext = jLongToContext(jContext); SCARDHANDLE hCard; 

	// ������� ���������� ���������
	std::vector<jint> vecProtocols = JNI::JavaGetIntArrayValue(env, jProtocols); 

	// ��������� �������������� ����
	DWORD dwSharedMode = jIntToDword(jShareMode     ); 
	DWORD dwProtocols  = jIntToDword(vecProtocols[0]); 

	// ��� ������� Unicode-������
	if (pFunctions->scardConnectW)
	{
		// ������� ��� �����������
		std::wstring reader = JNI::JavaGetStringValueUTF16(env, jReader); 

		// ������� ����� �� �����-������/������������
		Check(env, (*pFunctions->scardConnectW)(hContext, 
			reader.c_str(), dwSharedMode, dwProtocols, &hCard, &dwProtocols
		)); 
	}
	else {
		// ������� ��� �����������
		std::string reader = JNI::JavaGetStringValueUTF8(env, jReader); 

		// ������� ����� �� �����-������/������������
		Check(env, (*pFunctions->scardConnectA)(hContext, 
			reader.c_str(), dwSharedMode, dwProtocols, &hCard, &dwProtocols
		)); 
	}
	// ��������� ��������� ��������
	vecProtocols[0] = DwordToJInt(dwProtocols); 

	// �������� �������� � �������
	JNI::JavaSetIntArrayValue(env, jProtocols, 0, &vecProtocols[0], 1); 

	// ������� �������� ���������
	return HandleToJLong(hCard);  
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pcsc_Wrapper_reconnect(
	JNIEnv* env, jobject jModule, jlong jCard, 
	jint jShareMode, jintArray jProtocols, jint jInitMode) 
try {
	// �������� ������ �������
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	SCARDCONTEXT hCard = jLongToHandle(jCard); 

	// ������� ���������� ���������
	std::vector<jint> vecProtocols = JNI::JavaGetIntArrayValue(env, jProtocols); 

	// ��������� �������������� ����
	DWORD dwSharedMode = jIntToDword(jShareMode     ); 
	DWORD dwProtocols  = jIntToDword(vecProtocols[0]); 
	DWORD dwInitMode   = jIntToDword(jInitMode      ); 

	// ������ ����� �� �����-������/������������
	Check(env, (*pFunctions->scardReconnect)(hCard, 
		dwSharedMode, dwProtocols, dwInitMode, &dwProtocols
	)); 
	// ��������� ��������� ��������
	vecProtocols[0] = DwordToJInt(dwProtocols); 

	// �������� �������� � �������
	JNI::JavaSetIntArrayValue(env, jProtocols, 0, &vecProtocols[0], 1); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pcsc_Wrapper_disconnect(
	JNIEnv* env, jobject jModule, jlong jCard, jint jCloseMode)
try {
	// �������� ������ �������
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	SCARDCONTEXT hCard = jLongToHandle(jCard); 

	// ��������� �������������� ����
	DWORD dwCloseMode = jIntToDword(jCloseMode); 

	// ������� ����� �� �����-������/������������
	Check(env, (*pFunctions->scardDisconnect)(hCard, dwCloseMode)); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pcsc_Wrapper_getReaderStatus(
	JNIEnv* env, jobject jModule, jlong jCard, jobject jReaderStatus)
try {
	// �������� ������ �������
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// ������� ����� �������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_READER_STATUS)); 

	// ��������� �������������� ����
	SCARDCONTEXT hCard = jLongToHandle(jCard); DWORD dwState; DWORD dwProtocol; 
	
	// �������� ������ ��� ����������
	DWORD cbAtr = 32; BYTE atr[32]; DWORD cchReaders = 0; 
	
	// ��� ������� Unicode-������
	if (pFunctions->scardStatusW) 
	{ 
		// ���������� ��������� ������ ������
		LONG code = (*pFunctions->scardStatusW)(hCard, 
			NULL, &cchReaders, &dwState, &dwProtocol, atr, &cbAtr
		); 
		// ��������� ���������� ������
		if (code != SCARD_S_SUCCESS && code != SCARD_E_INSUFFICIENT_BUFFER) Check(env, code); 

		// �������� ������ ���������� �������
		std::wstring readers(cchReaders, 0); jint count = 0; 

		// �������� ��������� �����-�����
		Check(env, (*pFunctions->scardStatusW)(hCard, 
			&readers[0], &cchReaders, &dwState, &dwProtocol, atr, &cbAtr
		)); 
		// ������������� ������������ � ������
		JNI::LocalRef<jobjectArray> jReaders(env, MultiStringToStringArray(env, readers.c_str())); 

		// ������� ����� ������������
		JNI::JavaSetObject(env, jReaderStatus, jClass, "readers", "[Ljava.lang.String;", jReaders);
	} 
	else {
		// ���������� ��������� ������ ������
		LONG code = (*pFunctions->scardStatusA)(hCard, 
			NULL, &cchReaders, &dwState, &dwProtocol, atr, &cbAtr
		); 
		// ��������� ���������� ������
		if (code != SCARD_S_SUCCESS && code != SCARD_E_INSUFFICIENT_BUFFER) Check(env, code); 

		// �������� ������ ���������� �������
		std::string readers(cchReaders, 0); jint count = 0; 

		// �������� ��������� �����-�����
		Check(env, (*pFunctions->scardStatusA)(hCard, 
			&readers[0], &cchReaders, &dwState, &dwProtocol, atr, &cbAtr
		)); 
		// ������������� ������������ � ������
		JNI::LocalRef<jobjectArray> jReaders(env, MultiStringToStringArray(env, readers.c_str())); 

		// ������� ����� ������������
		JNI::JavaSetObject(env, jReaderStatus, jClass, "readers", "[Ljava.lang.String;", jReaders);
	}
	// ������� ������ ������
	JNI::LocalRef<jbyteArray> jATR(env, JNI::JavaNewByteArray(env, (jbyte*)atr, DwordToJSize(cbAtr))); 

	// ������� ATR
	JNI::JavaSetObject(env, jReaderStatus, jClass, "atr", "[B", jATR);

	// ������� ��������� � ��������
	JNI::JavaSetInt(env, jReaderStatus, jClass, "state"   , DwordToJInt(dwState   ));
	JNI::JavaSetInt(env, jReaderStatus, jClass, "protocol", DwordToJInt(dwProtocol));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

extern "C" JNIEXPORT 
jbyteArray JNICALL Java_aladdin_pcsc_Wrapper_getReaderAttribute(
	JNIEnv* env, jobject jModule, jlong jCard, jint jAttrId)
try {
	// �������� ������ �������
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	SCARDCONTEXT hCard = jLongToHandle(jCard); 

	// ��������� �������������� ����
	DWORD dwAttrId = jIntToDword(jAttrId); DWORD cbAttr = 0; 

	// ���������� ��������� ������ ������
	Check(env, (*pFunctions->scardGetAttrib)(hCard, dwAttrId, NULL, &cbAttr)); 

	// �������� ����� ���������� �������
	std::vector<BYTE> attr(cbAttr); 

	// ��������� ������ ��������
	if (cbAttr == 0) return JNI::JavaNewByteArray(env, NULL, cbAttr); 

	// �������� �������� ��������
	Check(env, (*pFunctions->scardGetAttrib)(hCard, dwAttrId, &attr[0], &cbAttr)); 

	// ������� �������� ��������
	return JNI::JavaNewByteArray(env, (jbyte*)&attr[0], cbAttr);
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pcsc_Wrapper_setReaderAttribute(
	JNIEnv* env, jobject jModule, jlong jCard, jint jAttrId, jbyteArray jAttr)
try {
	// �������� ������ �������
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	SCARDCONTEXT hCard = jLongToHandle(jCard); 

	// ��������� �������������� ����
	DWORD dwAttrId = jIntToDword(jAttrId); 

	// �������� �������� ��������
	std::vector<jbyte> vecAttr = JNI::JavaGetByteArrayValue(env, jAttr); 

	// ��������� ������ ��������
	if (vecAttr.size() == 0) 
	{
		// ���������� ������� �������� �������
		Check(env, (*pFunctions->scardSetAttrib)(hCard, dwAttrId, NULL, 0)); 
	}
	else {
		// ���������� ������� ���������� �������
		Check(env, (*pFunctions->scardSetAttrib)(
			hCard, dwAttrId, (BYTE*)&vecAttr[0], (DWORD)vecAttr.size()
		)); 
	}
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pcsc_Wrapper_beginTransaction(
	JNIEnv* env, jobject jModule, jlong jCard)
try {
	// �������� ������ �������
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	SCARDCONTEXT hCard = jLongToHandle(jCard); 

	// ������ ����������
	Check(env, (*pFunctions->scardBeginTransaction)(hCard)); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pcsc_Wrapper_endTransaction(
	JNIEnv* env, jobject jModule, jlong jCard, jint jCloseMode) 
try {
	// �������� ������ �������
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	SCARDCONTEXT hCard = jLongToHandle(jCard); 

	// ��������� �������������� ����
	DWORD dwCloseMode = jIntToDword(jCloseMode); 

	// ��������� ����������
	Check(env, (*pFunctions->scardEndTransaction)(hCard, dwCloseMode)); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

extern "C" JNIEXPORT 
jsize JNICALL Java_aladdin_pcsc_Wrapper_sendControl(
	JNIEnv* env, jobject jModule, jlong jCard, 
	jint jControlCode, jbyteArray jInBuffer, jbyteArray jOutBuffer)
try {
	// �������� ������ �������
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	SCARDCONTEXT hCard = jLongToHandle(jCard); 

	// ��������� �������������� ����
	DWORD dwControlCode = jIntToDword(jControlCode); 

	// �������� �������� �������
	std::vector<jbyte> vecInBuffer = JNI::JavaGetByteArrayValue(env, jInBuffer); 

	// ���������� ������ ��������� ������
	DWORD cbOutBuffer = jSizeToDword(env->GetArrayLength(jOutBuffer)); 

	// �������� ����� ���������� �������
	std::vector<jbyte> vecOutBuffer(cbOutBuffer); 

	// ������� ������� ������
	DWORD cbInBuffer = (DWORD)vecInBuffer.size(); if (cbInBuffer == 0)
	{
		// ��������� �������
		Check(env, (*pFunctions->scardControl)(
			hCard, dwControlCode, NULL, 0, 
			&vecOutBuffer[0], cbOutBuffer, &cbOutBuffer
		)); 
	}
	else {
		// ��������� �������
		Check(env, (*pFunctions->scardControl)(
			hCard, dwControlCode, &vecInBuffer, cbInBuffer, 
			&vecOutBuffer[0], cbOutBuffer, &cbOutBuffer
		)); 
	}
	// ����������� �������� ��������
	env->SetByteArrayRegion(jOutBuffer, 0, cbOutBuffer, &vecOutBuffer[0]); 

	return cbOutBuffer; 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

extern "C" JNIEXPORT 
jsize JNICALL Java_aladdin_pcsc_Wrapper_sendCommand(
	JNIEnv* env, jobject jModule, jlong jCard, 
	jint jProtocol, jbyteArray jSendBuffer, jbyteArray jRecvBuffer)
try {
	// �������� ������ �������
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	SCARDCONTEXT hCard = jLongToHandle(jCard); 

	// � ����������� �� ���������
	LPCSCARD_IO_REQUEST pioSendPci = NULL; switch (jIntToDword(jProtocol))
	{
	// ������� ������������ ���������
	case SCARD_PROTOCOL_RAW: pioSendPci = SCARD_PCI_RAW; break; 
	case SCARD_PROTOCOL_T0 : pioSendPci = SCARD_PCI_T0 ; break; 
	case SCARD_PROTOCOL_T1 : pioSendPci = SCARD_PCI_T1 ; break; 
	}
	// �������� �������� �������
	std::vector<jbyte> vecSendBuffer = JNI::JavaGetByteArrayValue(env, jSendBuffer); 

	// ��������� ������ �������
	if (vecSendBuffer.size() == 0) Check(env, SCARD_E_INVALID_PARAMETER); 

	// ���������� ������ ��������� ������
	DWORD cbRecvBuffer = jSizeToDword(env->GetArrayLength(jRecvBuffer)); 

	// �������� ����� ���������� �������
	std::vector<jbyte> vecRecvBuffer(cbRecvBuffer); 

	// ��������� �������
	Check(env, (*pFunctions->scardTransmit)(
		hCard, pioSendPci, (BYTE*)&vecSendBuffer[0], (DWORD)vecSendBuffer.size(), 
		NULL, (BYTE*)&vecRecvBuffer[0], &cbRecvBuffer
	)); 
	// ����������� �������� ��������
	env->SetByteArrayRegion(jRecvBuffer, 0, cbRecvBuffer, &vecSendBuffer[0]); 

	return cbRecvBuffer; 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

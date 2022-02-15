#include "stdafx.h"
#include "pcsc_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PCSC; 

///////////////////////////////////////////////////////////////////////////////
// Управление считывателями и смарт-картами
///////////////////////////////////////////////////////////////////////////////
extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pcsc_Wrapper_connect(
	JNIEnv* env, jobject jModule, jlong jContext, 
	jstring jReader, jint jShareMode, jintArray jProtocols)
try {
	// получить список функций
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	SCARDCONTEXT hContext = jLongToContext(jContext); SCARDHANDLE hCard; 

	// извлечь допустимые протоколы
	std::vector<jint> vecProtocols = JNI::JavaGetIntArrayValue(env, jProtocols); 

	// выполнить преобразование типа
	DWORD dwSharedMode = jIntToDword(jShareMode     ); 
	DWORD dwProtocols  = jIntToDword(vecProtocols[0]); 

	// при наличии Unicode-версии
	if (pFunctions->scardConnectW)
	{
		// извлечь имя считывателя
		std::wstring reader = JNI::JavaGetStringValueUTF16(env, jReader); 

		// создать сеанс со смарт-картой/считывателем
		Check(env, (*pFunctions->scardConnectW)(hContext, 
			reader.c_str(), dwSharedMode, dwProtocols, &hCard, &dwProtocols
		)); 
	}
	else {
		// извлечь имя считывателя
		std::string reader = JNI::JavaGetStringValueUTF8(env, jReader); 

		// создать сеанс со смарт-картой/считывателем
		Check(env, (*pFunctions->scardConnectA)(hContext, 
			reader.c_str(), dwSharedMode, dwProtocols, &hCard, &dwProtocols
		)); 
	}
	// сохранить выбранный протокол
	vecProtocols[0] = DwordToJInt(dwProtocols); 

	// изменить значения в массиве
	JNI::JavaSetIntArrayValue(env, jProtocols, 0, &vecProtocols[0], 1); 

	// вернуть значение описателя
	return HandleToJLong(hCard);  
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pcsc_Wrapper_reconnect(
	JNIEnv* env, jobject jModule, jlong jCard, 
	jint jShareMode, jintArray jProtocols, jint jInitMode) 
try {
	// получить список функций
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	SCARDCONTEXT hCard = jLongToHandle(jCard); 

	// извлечь допустимые протоколы
	std::vector<jint> vecProtocols = JNI::JavaGetIntArrayValue(env, jProtocols); 

	// выполнить преобразование типа
	DWORD dwSharedMode = jIntToDword(jShareMode     ); 
	DWORD dwProtocols  = jIntToDword(vecProtocols[0]); 
	DWORD dwInitMode   = jIntToDword(jInitMode      ); 

	// заново сеанс со смарт-картой/считывателем
	Check(env, (*pFunctions->scardReconnect)(hCard, 
		dwSharedMode, dwProtocols, dwInitMode, &dwProtocols
	)); 
	// сохранить выбранный протокол
	vecProtocols[0] = DwordToJInt(dwProtocols); 

	// изменить значения в массиве
	JNI::JavaSetIntArrayValue(env, jProtocols, 0, &vecProtocols[0], 1); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pcsc_Wrapper_disconnect(
	JNIEnv* env, jobject jModule, jlong jCard, jint jCloseMode)
try {
	// получить список функций
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	SCARDCONTEXT hCard = jLongToHandle(jCard); 

	// выполнить преобразование типа
	DWORD dwCloseMode = jIntToDword(jCloseMode); 

	// закрыть сеанс со смарт-картой/считывателем
	Check(env, (*pFunctions->scardDisconnect)(hCard, dwCloseMode)); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pcsc_Wrapper_getReaderStatus(
	JNIEnv* env, jobject jModule, jlong jCard, jobject jReaderStatus)
try {
	// получить список функций
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// указать класс объекта
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_READER_STATUS)); 

	// выполнить преобразование типа
	SCARDCONTEXT hCard = jLongToHandle(jCard); DWORD dwState; DWORD dwProtocol; 
	
	// выделить память для переменных
	DWORD cbAtr = 32; BYTE atr[32]; DWORD cchReaders = 0; 
	
	// при наличии Unicode-версии
	if (pFunctions->scardStatusW) 
	{ 
		// определить требуемый размер памяти
		LONG code = (*pFunctions->scardStatusW)(hCard, 
			NULL, &cchReaders, &dwState, &dwProtocol, atr, &cbAtr
		); 
		// проверить отсутствие ошибок
		if (code != SCARD_S_SUCCESS && code != SCARD_E_INSUFFICIENT_BUFFER) Check(env, code); 

		// выделить память требуемого размера
		std::wstring readers(cchReaders, 0); jint count = 0; 

		// получить состояние смарт-карты
		Check(env, (*pFunctions->scardStatusW)(hCard, 
			&readers[0], &cchReaders, &dwState, &dwProtocol, atr, &cbAtr
		)); 
		// преобразовать мультистроку в список
		JNI::LocalRef<jobjectArray> jReaders(env, MultiStringToStringArray(env, readers.c_str())); 

		// указать имена считывателей
		JNI::JavaSetObject(env, jReaderStatus, jClass, "readers", "[Ljava.lang.String;", jReaders);
	} 
	else {
		// определить требуемый размер памяти
		LONG code = (*pFunctions->scardStatusA)(hCard, 
			NULL, &cchReaders, &dwState, &dwProtocol, atr, &cbAtr
		); 
		// проверить отсутствие ошибок
		if (code != SCARD_S_SUCCESS && code != SCARD_E_INSUFFICIENT_BUFFER) Check(env, code); 

		// выделить память требуемого размера
		std::string readers(cchReaders, 0); jint count = 0; 

		// получить состояние смарт-карты
		Check(env, (*pFunctions->scardStatusA)(hCard, 
			&readers[0], &cchReaders, &dwState, &dwProtocol, atr, &cbAtr
		)); 
		// преобразовать мультистроку в список
		JNI::LocalRef<jobjectArray> jReaders(env, MultiStringToStringArray(env, readers.c_str())); 

		// указать имена считывателей
		JNI::JavaSetObject(env, jReaderStatus, jClass, "readers", "[Ljava.lang.String;", jReaders);
	}
	// создать массив байтов
	JNI::LocalRef<jbyteArray> jATR(env, JNI::JavaNewByteArray(env, (jbyte*)atr, DwordToJSize(cbAtr))); 

	// указать ATR
	JNI::JavaSetObject(env, jReaderStatus, jClass, "atr", "[B", jATR);

	// указать состояние и протокол
	JNI::JavaSetInt(env, jReaderStatus, jClass, "state"   , DwordToJInt(dwState   ));
	JNI::JavaSetInt(env, jReaderStatus, jClass, "protocol", DwordToJInt(dwProtocol));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

extern "C" JNIEXPORT 
jbyteArray JNICALL Java_aladdin_pcsc_Wrapper_getReaderAttribute(
	JNIEnv* env, jobject jModule, jlong jCard, jint jAttrId)
try {
	// получить список функций
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	SCARDCONTEXT hCard = jLongToHandle(jCard); 

	// выполнить преобразование типа
	DWORD dwAttrId = jIntToDword(jAttrId); DWORD cbAttr = 0; 

	// определить требуемый размер буфера
	Check(env, (*pFunctions->scardGetAttrib)(hCard, dwAttrId, NULL, &cbAttr)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> attr(cbAttr); 

	// проверить размер атрибута
	if (cbAttr == 0) return JNI::JavaNewByteArray(env, NULL, cbAttr); 

	// получить значение атрибута
	Check(env, (*pFunctions->scardGetAttrib)(hCard, dwAttrId, &attr[0], &cbAttr)); 

	// вернуть значение атрибута
	return JNI::JavaNewByteArray(env, (jbyte*)&attr[0], cbAttr);
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pcsc_Wrapper_setReaderAttribute(
	JNIEnv* env, jobject jModule, jlong jCard, jint jAttrId, jbyteArray jAttr)
try {
	// получить список функций
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	SCARDCONTEXT hCard = jLongToHandle(jCard); 

	// выполнить преобразование типа
	DWORD dwAttrId = jIntToDword(jAttrId); 

	// получить значение атрибута
	std::vector<jbyte> vecAttr = JNI::JavaGetByteArrayValue(env, jAttr); 

	// проверить размер атрибута
	if (vecAttr.size() == 0) 
	{
		// установить атрибут нулевого размера
		Check(env, (*pFunctions->scardSetAttrib)(hCard, dwAttrId, NULL, 0)); 
	}
	else {
		// установить атрибут ненулевого размера
		Check(env, (*pFunctions->scardSetAttrib)(
			hCard, dwAttrId, (BYTE*)&vecAttr[0], (DWORD)vecAttr.size()
		)); 
	}
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pcsc_Wrapper_beginTransaction(
	JNIEnv* env, jobject jModule, jlong jCard)
try {
	// получить список функций
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	SCARDCONTEXT hCard = jLongToHandle(jCard); 

	// начать транзакцию
	Check(env, (*pFunctions->scardBeginTransaction)(hCard)); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pcsc_Wrapper_endTransaction(
	JNIEnv* env, jobject jModule, jlong jCard, jint jCloseMode) 
try {
	// получить список функций
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	SCARDCONTEXT hCard = jLongToHandle(jCard); 

	// выполнить преобразование типа
	DWORD dwCloseMode = jIntToDword(jCloseMode); 

	// завершить транзакцию
	Check(env, (*pFunctions->scardEndTransaction)(hCard, dwCloseMode)); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

extern "C" JNIEXPORT 
jsize JNICALL Java_aladdin_pcsc_Wrapper_sendControl(
	JNIEnv* env, jobject jModule, jlong jCard, 
	jint jControlCode, jbyteArray jInBuffer, jbyteArray jOutBuffer)
try {
	// получить список функций
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	SCARDCONTEXT hCard = jLongToHandle(jCard); 

	// выполнить преобразование типа
	DWORD dwControlCode = jIntToDword(jControlCode); 

	// получить значение команды
	std::vector<jbyte> vecInBuffer = JNI::JavaGetByteArrayValue(env, jInBuffer); 

	// определить размер выходного буфера
	DWORD cbOutBuffer = jSizeToDword(env->GetArrayLength(jOutBuffer)); 

	// выделить буфер требуемого размера
	std::vector<jbyte> vecOutBuffer(cbOutBuffer); 

	// указать размеры буфера
	DWORD cbInBuffer = (DWORD)vecInBuffer.size(); if (cbInBuffer == 0)
	{
		// выполнить команду
		Check(env, (*pFunctions->scardControl)(
			hCard, dwControlCode, NULL, 0, 
			&vecOutBuffer[0], cbOutBuffer, &cbOutBuffer
		)); 
	}
	else {
		// выполнить команду
		Check(env, (*pFunctions->scardControl)(
			hCard, dwControlCode, &vecInBuffer, cbInBuffer, 
			&vecOutBuffer[0], cbOutBuffer, &cbOutBuffer
		)); 
	}
	// скопировать значение атрибута
	env->SetByteArrayRegion(jOutBuffer, 0, cbOutBuffer, &vecOutBuffer[0]); 

	return cbOutBuffer; 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

extern "C" JNIEXPORT 
jsize JNICALL Java_aladdin_pcsc_Wrapper_sendCommand(
	JNIEnv* env, jobject jModule, jlong jCard, 
	jint jProtocol, jbyteArray jSendBuffer, jbyteArray jRecvBuffer)
try {
	// получить список функций
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	SCARDCONTEXT hCard = jLongToHandle(jCard); 

	// в зависимости от протокола
	LPCSCARD_IO_REQUEST pioSendPci = NULL; switch (jIntToDword(jProtocol))
	{
	// указать используемый заголовок
	case SCARD_PROTOCOL_RAW: pioSendPci = SCARD_PCI_RAW; break; 
	case SCARD_PROTOCOL_T0 : pioSendPci = SCARD_PCI_T0 ; break; 
	case SCARD_PROTOCOL_T1 : pioSendPci = SCARD_PCI_T1 ; break; 
	}
	// получить значение команды
	std::vector<jbyte> vecSendBuffer = JNI::JavaGetByteArrayValue(env, jSendBuffer); 

	// проверить размер команды
	if (vecSendBuffer.size() == 0) Check(env, SCARD_E_INVALID_PARAMETER); 

	// определить размер выходного буфера
	DWORD cbRecvBuffer = jSizeToDword(env->GetArrayLength(jRecvBuffer)); 

	// выделить буфер требуемого размера
	std::vector<jbyte> vecRecvBuffer(cbRecvBuffer); 

	// выполнить команду
	Check(env, (*pFunctions->scardTransmit)(
		hCard, pioSendPci, (BYTE*)&vecSendBuffer[0], (DWORD)vecSendBuffer.size(), 
		NULL, (BYTE*)&vecRecvBuffer[0], &cbRecvBuffer
	)); 
	// скопировать значение атрибута
	env->SetByteArrayRegion(jRecvBuffer, 0, cbRecvBuffer, &vecSendBuffer[0]); 

	return cbRecvBuffer; 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

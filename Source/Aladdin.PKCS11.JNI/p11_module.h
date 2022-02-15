#pragma once

namespace Aladdin { namespace PKCS11 {

///////////////////////////////////////////////////////////////////////////////
// Структура параметров для функции обратного вызова
///////////////////////////////////////////////////////////////////////////////
struct NotifyData {
	JavaVM*	jvm;			// используемая Java-машина
	jint	version;		// версия JNI
	jobject	jNotify;		// обработчик оповещения
	jobject jApplication;	// данные для обработчика

	// конструктор / деструктор
	NotifyData(const class ModuleEntry*, jobject, jobject); ~NotifyData();

	// оповестить обработчик
	CK_RV Invoke(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event) const; 
};
///////////////////////////////////////////////////////////////////////////////
// Глобальные данные модуля PKCS#11
///////////////////////////////////////////////////////////////////////////////
class ModuleEntry
{
	// узел списка зарегистрированных обработчиков
	private: struct NotifyNode { CK_SLOT_ID	ckSlotID; NotifyData* notifyData; };

	// используемая Java-машина и версия JNI
	private: JavaVM* jvm; private: jint	version;	
	// базовый адрес модуля и список функций PKCS#11
	private: void* hModule; CK_FUNCTION_LIST_PTR ckFunctionListPtr;

	// список зарегистрированных обработчиков
	private: std::map<CK_SESSION_HANDLE, NotifyNode> handlers; private:	CK_VOID_PTR lock; 

	// конструктор/деструктор
	public: ModuleEntry(JNIEnv*, jstring); public: ~ModuleEntry();

	// используемая Java-машина и версия интерфейса JNI
	public: JavaVM* JVM    () const { return jvm;     }
	public: jint    Version() const { return version; }

	// список функций PKCS#11
	public: CK_FUNCTION_LIST_PTR FunctionList() const { return ckFunctionListPtr; }

	// выполнить инициализацию/освобождение ресурсов
	public: void Initialize(JNIEnv*, jlong); void Finalize(JNIEnv*);

	// добавить обработчик оповещения в список
	public:	void AddNotifyHandler(JNIEnv* env, CK_SLOT_ID ckSlotID, 
		CK_SESSION_HANDLE hSession, NotifyData* notifyData
	); 
	// удалить обработчик оповещения из списка
	public:	void RemoveNotifyHandler(JNIEnv* env, CK_SESSION_HANDLE hSession); 
	// удалить обработчики оповещения из списка
	public:	void RemoveNotifyHandlers(JNIEnv* env, CK_SLOT_ID ckSlotID); 
};

}}

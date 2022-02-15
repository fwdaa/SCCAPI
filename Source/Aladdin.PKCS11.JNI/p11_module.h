#pragma once

namespace Aladdin { namespace PKCS11 {

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� ��� ������� ��������� ������
///////////////////////////////////////////////////////////////////////////////
struct NotifyData {
	JavaVM*	jvm;			// ������������ Java-������
	jint	version;		// ������ JNI
	jobject	jNotify;		// ���������� ����������
	jobject jApplication;	// ������ ��� �����������

	// ����������� / ����������
	NotifyData(const class ModuleEntry*, jobject, jobject); ~NotifyData();

	// ���������� ����������
	CK_RV Invoke(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event) const; 
};
///////////////////////////////////////////////////////////////////////////////
// ���������� ������ ������ PKCS#11
///////////////////////////////////////////////////////////////////////////////
class ModuleEntry
{
	// ���� ������ ������������������ ������������
	private: struct NotifyNode { CK_SLOT_ID	ckSlotID; NotifyData* notifyData; };

	// ������������ Java-������ � ������ JNI
	private: JavaVM* jvm; private: jint	version;	
	// ������� ����� ������ � ������ ������� PKCS#11
	private: void* hModule; CK_FUNCTION_LIST_PTR ckFunctionListPtr;

	// ������ ������������������ ������������
	private: std::map<CK_SESSION_HANDLE, NotifyNode> handlers; private:	CK_VOID_PTR lock; 

	// �����������/����������
	public: ModuleEntry(JNIEnv*, jstring); public: ~ModuleEntry();

	// ������������ Java-������ � ������ ���������� JNI
	public: JavaVM* JVM    () const { return jvm;     }
	public: jint    Version() const { return version; }

	// ������ ������� PKCS#11
	public: CK_FUNCTION_LIST_PTR FunctionList() const { return ckFunctionListPtr; }

	// ��������� �������������/������������ ��������
	public: void Initialize(JNIEnv*, jlong); void Finalize(JNIEnv*);

	// �������� ���������� ���������� � ������
	public:	void AddNotifyHandler(JNIEnv* env, CK_SLOT_ID ckSlotID, 
		CK_SESSION_HANDLE hSession, NotifyData* notifyData
	); 
	// ������� ���������� ���������� �� ������
	public:	void RemoveNotifyHandler(JNIEnv* env, CK_SESSION_HANDLE hSession); 
	// ������� ����������� ���������� �� ������
	public:	void RemoveNotifyHandlers(JNIEnv* env, CK_SLOT_ID ckSlotID); 
};

}}

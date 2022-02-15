#pragma once

namespace Aladdin { namespace CAPI { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// ��������� �������
	///////////////////////////////////////////////////////////////////////////
	public ref class Handle abstract : SafeHandle
	{
		// ��������� ������� ������
		public:	generic <typename T> where T : Handle static T AddRef(T handle) 
		{ 
			// ��������� ������� ������
			bool success = false; handle->DangerousAddRef(IN OUT success); 
			
			// ��������� ��������� ������
			if (!success) throw gcnew Win32Exception(NTE_FAIL); return handle; 
		}
		// ��������� ������� ������
		public:	generic <typename T> where T : Handle static void Release(T handle) 
		{ 
			// ��������� ������� ������
			if (handle != nullptr) handle->DangerousRelease(); 
		}
		// �����������
		public: Handle() : SafeHandle(IntPtr::Zero, true) {}

		// ������� ������������� ���������
		public: virtual property bool IsInvalid 
		{ 
			// ������� ������������� ���������
			[SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
			bool get() override { return handle == IntPtr::Zero; }
		}
		// ���������� ������
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
		{ 
			// �������� ����� �����������
			GC::SuppressFinalize(this); return true; 
		} 
		// �������� ���������
		public: property void* Value { void* get() { return handle.ToPointer(); }}   

		// �������� ��������
		public: virtual DWORD GetSafeParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags) = 0; 
		// �������� ��������
		public: virtual DWORD GetParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags) = 0; 
		// ���������� ��������
		public: virtual void SetParam(DWORD param, IntPtr ptr, DWORD flags) = 0; 

		// �������� �������� ���������
		public: array<BYTE>^ GetSafeParam(DWORD param, DWORD flags); 
		// �������� �������� ���������
		public: array<BYTE>^ GetParam(DWORD param, DWORD flags); 
		// �������� �������� ���������
		public: String^ GetString(DWORD param, DWORD flags); 
		// �������� �������� ���������
		public: DWORD GetLong(DWORD param, DWORD flags); 

		// ���������� �������� ���������
		public: void SetParam(DWORD param, array<BYTE>^ value, DWORD flags); 
		// ���������� �������� ���������
		public: void SetString(DWORD param, String^ value, DWORD flags); 
		// ���������� �������� ���������
		public: void SetLong(DWORD param, DWORD value, DWORD flags); 
	};
	///////////////////////////////////////////////////////////////////////////
	// ��������� ��������� �����������
	///////////////////////////////////////////////////////////////////////////
	public ref class HashHandle : Handle
	{
        // ��������� ���������� � ������������� ������� ����������
		private: Handle^ providerHandle; public: initonly BOOL SSPI; 

		// �����������
		public: HashHandle(Handle^ providerHandle, HCRYPTHASH hHash, BOOL sspi) 
        { 
            // ��������� ���������� ���������
            SetHandle((IntPtr)(PVOID)hHash); SSPI = sspi; 

			// ��������� ��������� ����������
			this->providerHandle = Handle::AddRef(providerHandle); 
        }  
		// ���������� ������
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override; 

		// ��������� ����������
		public: property Handle^ ProviderHandle 
		{ 
			// ��������� ����������
			Handle^ get() { return providerHandle; }
		}   
		// ��������� ��������� �����������
		public: property HCRYPTHASH Value
		{ 
			// ��������� ��������� �����������
			HCRYPTHASH get() { return (HCRYPTHASH)handle.ToPointer(); }
		}   
		// ������� ����� ��������� �����������
		public: HashHandle^ Duplicate(DWORD flags); 

		// �������� �������� ���������
		public: virtual DWORD GetSafeParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// �������� �������� ���������
		public: virtual DWORD GetParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// ���������� �������� ���������
		public: virtual void SetParam(DWORD param, IntPtr ptr, DWORD flags) override; 

		// ������������ ������ 
		public: void HashData(array<BYTE>^ data, DWORD dataOff, DWORD dataLen, DWORD flags);
	};
	///////////////////////////////////////////////////////////////////////////
	// ��������� �����
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyHandle: Handle
	{
        // ��������� ���������� � ������������� ������� ����������
		private: Handle^ providerHandle; public: initonly BOOL SSPI; 

		// �����������
		public: KeyHandle(Handle^ providerHandle, HCRYPTKEY hKey, BOOL sspi) 
        {
            // ��������� ���������� ���������
            SetHandle((IntPtr)(PVOID)hKey); SSPI = sspi; 

			// ��������� ��������� ����������
			this->providerHandle = Handle::AddRef(providerHandle); 
		} 
		// ���������� ������
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override; 

		// ��������� ����������
		public: property Handle^ ProviderHandle 
		{ 
			// ��������� ����������
			Handle^ get() { return providerHandle; }
		}   
		// ��������� �����
		public: property HCRYPTKEY Value 
		{ 
			// ��������� �����
			HCRYPTKEY get() { return (HCRYPTKEY)handle.ToPointer(); }
		}   
		// ������� ����� �����
		public: KeyHandle^ Duplicate(DWORD flags);

		// �������� �������� ���������
		public: virtual DWORD GetSafeParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// �������� �������� ���������
		public: virtual DWORD GetParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// ���������� �������� ���������
		public: virtual void SetParam(DWORD param, IntPtr ptr, DWORD flags) override; 

		// �������������� ����
		public: DWORD Export(KeyHandle^ hExportKey, DWORD blobType, 
			DWORD flags, IntPtr ptrBlob, DWORD cbBlob
		); 
		// ����������� ������ 
		public: DWORD Encrypt(array<BYTE>^ data, DWORD dataOff, DWORD dataLen, 
			BOOL final, DWORD flags, array<BYTE>^ buffer, DWORD bufferOff 
		); 
		// ����������� ������ 
		public: array<BYTE>^ Encrypt(array<BYTE>^ data, DWORD flags);

		// ������������ ������ 
		public: DWORD Decrypt(array<BYTE>^ data, DWORD dataOff, DWORD dataLen, 
			BOOL final, DWORD flags, array<BYTE>^ buffer, DWORD bufferOff 
		);
		// ������������ ������ 
		public: array<BYTE>^ Decrypt(array<BYTE>^ data, DWORD flags);

		// ��������� ������� ���-��������
		public: void VerifySignature(HashHandle^ hHash, array<BYTE>^ signature, DWORD flags);  
	}; 
	///////////////////////////////////////////////////////////////////////////
	// ��������� ���������
	///////////////////////////////////////////////////////////////////////////
	public ref class ContextHandle : Handle
	{
        // ������������� ������� ����������
        public: initonly BOOL SSPI;

		// �����������
		public: ContextHandle(HCRYPTPROV hContext, BOOL sspi) 
        {
            // ��������� ���������� ���������        
            SetHandle((IntPtr)(PVOID)hContext); SSPI = sspi; 
        }
		// ���������� ������
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override; 

		// ��������� ��������
		public: property HCRYPTPROV Value 
		{ 
			// ��������� ��������
			HCRYPTPROV get() { return (HCRYPTPROV)handle.ToPointer(); }
		}   
		// �������� �������� 
		public: virtual DWORD GetSafeParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// �������� �������� 
		public: virtual DWORD GetParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// ���������� �������� 
		public: virtual void SetParam(DWORD param, IntPtr ptr, DWORD flags) override; 

		// ������������� ��������� ������
		public: void Generate(array<BYTE>^ buffer, DWORD bufferOff, DWORD bufferLen); 
		// ������� �������� �����������
		public: HashHandle^ CreateHash(ALG_ID algID, KeyHandle^ hKey, DWORD flags);

		// ����������� ����
		public: KeyHandle^ DeriveKey(ALG_ID algID, HashHandle^ hHash, DWORD flags);
		// ������� ����
		public: KeyHandle^ GenerateKey(ALG_ID algID, DWORD flags);
		// ������������� ����
		public: KeyHandle^ ImportKey(KeyHandle^ hImportKey, IntPtr ptrBlob, DWORD cbBlob, DWORD flags);  
	}; 
	///////////////////////////////////////////////////////////////////////////
	// ��������� ����������
	///////////////////////////////////////////////////////////////////////////
	public ref class ContainerHandle : ContextHandle
	{
		// �����������
		public: ContainerHandle(HCRYPTPROV hContainer, BOOL sspi) : ContextHandle(hContainer, sspi) {}
		 
		// ��� ����������
		public: property DWORD ProviderType { DWORD get() { return GetLong(PP_PROVTYPE, 0); }}	
		// ��� ���������� 
		public: property String^ ProviderName { String^ get() { return GetString(PP_NAME, 0); }}
		// ��� ����������
		public: property String^ Name { String^ get() { return GetString(PP_CONTAINER, 0); }}

		// �������� ������ ����
		public: KeyHandle^ GetUserKey(DWORD keyType);  

		// ��������� ���-��������
		public: array<BYTE>^ SignHash(DWORD keyType, HashHandle^ hHash, DWORD flags);  
	}; 
	///////////////////////////////////////////////////////////////////////////
	// ��������� ���������
	///////////////////////////////////////////////////////////////////////////
	public ref class StoreHandle : ContextHandle
	{
		// ������� ���������
		public: StoreHandle(DWORD type, String^ name, String^ reader, DWORD flags, BOOL sspi); 
		// �����������
		public: StoreHandle(HCRYPTPROV hStore, BOOL sspi) : ContextHandle(hStore, sspi) {}
		 
		// ��� ����������
		public: property DWORD ProviderType { DWORD get() { return GetLong(PP_PROVTYPE, 0); }}	
		// ��� ����������
		public: property String^ ProviderName { String^ get() { return GetString(PP_NAME, 0); }}

		// ����������� �������
		public: array<String^>^ Enumerate(DWORD paramID, DWORD flags); 
		// ����������� ����������
		public: array<String^>^ EnumerateContainers(DWORD flags); 

		// �������/������� ���������
		public: ContainerHandle^ AcquireContainer(String^ name, DWORD flags); 
		// ������� ���������
		public: void DeleteContainer(String^ szName, DWORD flags); 
	}; 
	///////////////////////////////////////////////////////////////////////////
	// ��������� ����������
	///////////////////////////////////////////////////////////////////////////
	public ref class ProviderHandle : StoreHandle
	{
		// ������� ���������
		public: ProviderHandle(DWORD type, String^ name, DWORD flags, BOOL sspi); 
		// �����������
		public: ProviderHandle(HCRYPTPROV hProvider, BOOL sspi) : StoreHandle(hProvider, sspi) {}
		 
		// ��� ����������
		public: property DWORD Type { DWORD get() { return ProviderType; }}	
		// ��� ����������
		public: property String^ Name { String^ get() { return ProviderName; }}

		// ������� ���������
		public: StoreHandle^ AcquireStore(String^ name, DWORD flags); 
	}; 
}}}

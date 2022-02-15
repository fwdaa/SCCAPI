#pragma once

namespace Aladdin { namespace CAPI { namespace CNG 
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
		protected: Handle() : SafeHandle(IntPtr::Zero, true) {}

		// ������� ������������� ���������
		public: virtual property bool IsInvalid 
		{ 
			// ������� ������������� ���������
			[SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
			bool get() override { return handle == IntPtr::Zero; }
		}
		// ����������
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
        {
			// �������� ����� �����������
			GC::SuppressFinalize(this); return true; 
        }
		// �������� ��������
		public: virtual DWORD GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) = 0; 
		// �������� ��������
		public: virtual DWORD GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) = 0; 
		// ���������� ��������
		public: virtual void SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) = 0; 

		// �������� �������� ���������
		public: array<BYTE>^ GetSafeParam(String^ param, DWORD flags); 
		// �������� �������� ���������
		public: array<BYTE>^ GetParam(String^ param, DWORD flags); 
		// �������� �������� ���������
		public: String^ GetString(String^ param, DWORD flags); 
		// �������� �������� ���������
		public: DWORD GetLong(String^ param, DWORD flags); 

		// ���������� �������� ���������
		public: void SetParam(String^ param, array<BYTE>^ value, DWORD flags); 
		// ���������� �������� ���������
		public: void SetString(String^ param, String^ value, DWORD flags); 
		// ���������� �������� ���������
		public: void SetLong(String^ param, DWORD value, DWORD flags); 
	};
	///////////////////////////////////////////////////////////////////////////
	// ��������� ��������� �����������
	///////////////////////////////////////////////////////////////////////////
	public ref class BHashHandle : Handle
	{
		// ������ ��� �������
		private: IntPtr	ptrObj;	private: int cbObj;

		// �����������
		public: BHashHandle(BCRYPT_HASH_HANDLE hObject, IntPtr ptrObj, int cbObj) 
		{ 
			// ���������� ���������
			SetHandle((IntPtr)(PVOID)hObject); this->ptrObj = ptrObj; this->cbObj = cbObj;
		}
		// ����������
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
		{
			// ������� ������� �������
            if (!Handle::ReleaseHandle()) return false;  
			
			// ���������� ��������� ������� 
			bool success = SUCCEEDED(::BCryptDestroyHash(Value)); 
			
			// ���������� ������ �������
			if (ptrObj != IntPtr::Zero) Marshal::FreeHGlobal(ptrObj); return success; 
		} 
		// ��������� ��������� �����������
		public: property BCRYPT_HASH_HANDLE Value 
		{ 
			// ��������� ��������� �����������
			BCRYPT_HASH_HANDLE get() { return (BCRYPT_HASH_HANDLE)handle.ToPointer(); }
		} 
		// �������� ��������
		public: virtual DWORD GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// �������� ��������
		public: virtual DWORD GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// ���������� ��������
		public: virtual void SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 

		// ������� ����� ��������� �����������
		public: BHashHandle^ Duplicate(DWORD flags); 

		// ������������ ������ 
		public: void HashData(array<BYTE>^ data, int dataOff, int dataLen, DWORD flags);

		// �������� ���-��������
		public: array<BYTE>^ FinishHash(DWORD flags); 
	};
	///////////////////////////////////////////////////////////////////////////
	// ��������� ������������ �������
	///////////////////////////////////////////////////////////////////////////
	public ref class BSecretHandle : Handle
	{
		// �����������
		public: BSecretHandle(BCRYPT_SECRET_HANDLE hObject) 
		{ 
			// ���������� ���������
			SetHandle((IntPtr)(PVOID)hObject); 
		}
		// ����������
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
		{ 
			// ������� ������� �������
            if (!Handle::ReleaseHandle()) return false; 
			
			// ���������� ��������� ������� 
			return SUCCEEDED(::BCryptDestroySecret(Value)); 
		} 
		// ��������� ������������ �������
		public: property BCRYPT_SECRET_HANDLE Value 
		{ 
			// ��������� ������������ �������
			BCRYPT_SECRET_HANDLE get() { return (BCRYPT_SECRET_HANDLE)handle.ToPointer(); }
		} 
		// �������� ��������
		public: virtual DWORD GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// �������� ��������
		public: virtual DWORD GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// ���������� ��������
		public: virtual void SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 

		// ����������� ����
		public: array<BYTE>^ DeriveKey(String^ nameKDF, DWORD keySize, IntPtr params, DWORD flags); 
	};
	///////////////////////////////////////////////////////////////////////////
	// ��������� ������������ �������
	///////////////////////////////////////////////////////////////////////////
	public ref class NSecretHandle : Handle
	{
		// �����������
		public: NSecretHandle(NCRYPT_SECRET_HANDLE hObject) 
		{ 
			// ���������� ���������
			SetHandle((IntPtr)(PVOID)hObject); 
		}
		// ����������
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
		{ 
            // ������� ������� �������
            if (!Handle::ReleaseHandle()) return false; 
			
			// ���������� ������
			return ::NCryptFreeObject(Value) == ERROR_SUCCESS;
		} 
		// ��������� ������������ �������
		public: property NCRYPT_SECRET_HANDLE Value 
		{ 
			// ��������� ������������ �������
			NCRYPT_SECRET_HANDLE get() { return (NCRYPT_SECRET_HANDLE)handle.ToPointer(); }
		} 
		// �������� ��������
		public: virtual DWORD GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// �������� ��������
		public: virtual DWORD GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// ���������� ��������
		public: virtual void SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 

		// ����������� ����
		public: array<BYTE>^ DeriveKey(String^ nameKDF, DWORD keySize, IntPtr params, DWORD flags); 
	};
	///////////////////////////////////////////////////////////////////////////
	// ��������� �����
	///////////////////////////////////////////////////////////////////////////
	public ref class BKeyHandle : Handle
	{
		// ������ ��� �������
		private: IntPtr	ptrObj;	private: int cbObj;

		// ������������� �������� ����
		public: static BKeyHandle^ ImportPublicKeyInfo(
            ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo, DWORD flags
        ); 
		// �����������
		public: BKeyHandle(BCRYPT_KEY_HANDLE hObject, IntPtr ptrObj, int cbObj)
		{ 
			// ���������� ���������
			SetHandle((IntPtr)(PVOID)hObject); this->ptrObj = ptrObj; this->cbObj = cbObj;
		}
		// ����������
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
		{ 
			// ������� ������� �������
            if (!Handle::ReleaseHandle()) return false; 
			
			// ���������� ������
			bool success = SUCCEEDED(::BCryptDestroyKey(Value));
 
			// ���������� ������ �������
			if (ptrObj != IntPtr::Zero) Marshal::FreeHGlobal(ptrObj); return success; 
		} 
		// ��������� �����
		public: property BCRYPT_KEY_HANDLE Value 
		{ 
			// ��������� �����
			BCRYPT_KEY_HANDLE get() { return (BCRYPT_KEY_HANDLE)handle.ToPointer(); }
		}   
		// �������� ��������
		public: virtual DWORD GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// �������� ��������
		public: virtual DWORD GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// ���������� ��������
		public: virtual void SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 

		// ������� ����� �����
		public: BKeyHandle^ Duplicate(DWORD flags);

		// �������������� ����
		public: DWORD Export(BKeyHandle^ hExportKey, String^ blobType, 
			DWORD flags, IntPtr ptrBlob, DWORD cbBlob
		); 
#if _WIN32_WINNT >= 0x0602
		// ����������� ����
		public: array<BYTE>^ DeriveKey(DWORD keySize, IntPtr params, DWORD flags); 
#endif
		// ����������� ����
		public: BSecretHandle^ AgreementSecret(BKeyHandle^ hPublicKey, DWORD flags); 

		// ����������� ������ 
		public: DWORD Encrypt(array<BYTE>^ iv, array<BYTE>^ data, DWORD dataOff, 
			DWORD dataLen, DWORD flags, array<BYTE>^ buffer, DWORD bufferOff 
		); 
		// ������������ ������ 
		public: DWORD Decrypt(array<BYTE>^ iv, array<BYTE>^ data, DWORD dataOff, 
			DWORD dataLen, DWORD flags, array<BYTE>^ buffer, DWORD bufferOff 
		);
		// ����������� ������ 
		public: array<BYTE>^ Encrypt(IntPtr padding, array<BYTE>^ data, DWORD flags);
		// ������������ ������ 
		public: array<BYTE>^ Decrypt(IntPtr padding, array<BYTE>^ data, DWORD flags);

		// ��������� ���-��������
		public: array<BYTE>^ SignHash(IntPtr padding, array<BYTE>^ hash, DWORD flags);  
		// ��������� ������� ���-��������
		public: void VerifySignature(IntPtr padding, array<BYTE>^ hash, array<BYTE>^ signature, DWORD flags);  
	}; 
	///////////////////////////////////////////////////////////////////////////
	// ��������� �����
	///////////////////////////////////////////////////////////////////////////
	public ref class NKeyHandle : Handle
	{
		// �����������
		public: NKeyHandle(NCRYPT_KEY_HANDLE hObject) 
		{
			// ���������� ���������
			SetHandle((IntPtr)(PVOID)hObject); 
		}
        // ��������� �������� �����
        public: void Finalize(DWORD flags);   

		// ����������
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
		{ 
			// ������� ������� �������
            if (!Handle::ReleaseHandle()) return false; 
			
			// ���������� ��������� ������� 
			return ::NCryptFreeObject(Value) == ERROR_SUCCESS;
		} 
		// ��������� �����
		public: property NCRYPT_KEY_HANDLE Value 
		{ 
			// ��������� �����
			NCRYPT_KEY_HANDLE get() { return (NCRYPT_KEY_HANDLE)handle.ToPointer(); }
		}   
		// �������� ��������
		public: virtual DWORD GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// �������� ��������
		public: virtual DWORD GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// ���������� ��������
		public: virtual void SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 

		// �������������� ����
		public: DWORD Export(NKeyHandle^ hExportKey, String^ blobType, 
			DWORD flags, IntPtr ptrBlob, DWORD cbBlob
		); 
#if _WIN32_WINNT >= 0x0602
		// ����������� ����
		public: array<BYTE>^ DeriveKey(DWORD keySize, IntPtr params, DWORD flags); 
#endif
		// ����������� ����
		public: NSecretHandle^ AgreementSecret(NKeyHandle^ hPublicKey, DWORD flags); 

		// ����������� ������ 
		public: array<BYTE>^ Encrypt(IntPtr padding, array<BYTE>^ data, DWORD flags);
		// ������������ ������ 
		public: array<BYTE>^ Decrypt(IntPtr padding, array<BYTE>^ data, DWORD flags);

		// ��������� ���-��������
		public: array<BYTE>^ SignHash(IntPtr padding, array<BYTE>^ hash, DWORD flags);  
		// ��������� ������� ���-��������
		public: void VerifySignature(IntPtr padding, array<BYTE>^ hash, array<BYTE>^ signature, DWORD flags);  
	}; 
	///////////////////////////////////////////////////////////////////////////
	// ��������� ���������� ���������
	///////////////////////////////////////////////////////////////////////////
	public ref class BProviderHandle : Handle
	{
		// �����������
		public: BProviderHandle(String^ provider, String^ alg, DWORD flags); 

		// �����������
		public: BProviderHandle(BCRYPT_ALG_HANDLE hObject) 
		{ 	
			// ���������� ���������
			SetHandle((IntPtr)(PVOID)hObject); 
		} 
		// ����������
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
		{ 
			// ������� ������� �������
            if (!Handle::ReleaseHandle()) return false;  
			
			// ���������� ��������� ������� 
			return SUCCEEDED(::BCryptCloseAlgorithmProvider(Value, 0));
		}
		// ��������� ���������� ���������
		public: property BCRYPT_ALG_HANDLE Value 
		{ 
			// ��������� ���������� ���������
			BCRYPT_ALG_HANDLE get() { return (BCRYPT_ALG_HANDLE)handle.ToPointer(); }
		}   
		// �������� ��������
		public: virtual DWORD GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// �������� ��������
		public: virtual DWORD GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// ���������� ��������
		public: virtual void SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 

		// ������������� ��������� ������
		public: void Generate(array<BYTE>^ buffer, 
			DWORD bufferOff, DWORD bufferLen, DWORD flags
		); 
		// ������� �������� �����������
		public: BHashHandle^ CreateHash(array<BYTE>^ key, DWORD flags);

		// ������� ����
		public: BKeyHandle^ GenerateKey(DWORD flags);
		// ������������� ����
		public: BKeyHandle^ ImportKey(BKeyHandle^ hImportKey, 
			String^ blobType, IntPtr ptrData, DWORD cbData, DWORD flags
		);
		// ������ �������� ���� ������
		public: BKeyHandle^ CreateKeyPair(DWORD length, DWORD flags);
		// ��������� �������� ���� ������
		public: void FinalizeKeyPair(BKeyHandle^ hKeyPair, DWORD flags);

		// ������������� �������� ����
		public: BKeyHandle^ ImportKeyPair(BKeyHandle^ hImportKey, 
			String^ blobType, IntPtr ptrData, DWORD cbData, DWORD flags
		);  
	}; 
	///////////////////////////////////////////////////////////////////////////
	// ��������� ����������
	///////////////////////////////////////////////////////////////////////////
	public ref class NProviderHandle : Handle
	{
		// �����������
		public: NProviderHandle(String^ name, DWORD flags); 

		// �����������
		public: NProviderHandle(NCRYPT_PROV_HANDLE hObject) 
		{ 	
			// ���������� ���������
			SetHandle((IntPtr)(PVOID)hObject); 
		} 
		// ����������
		protected: [SecurityPermission(SecurityAction::LinkDemand, UnmanagedCode = true)]
		virtual bool ReleaseHandle() override
		{ 
			// ������� ������� �������
            if (!Handle::ReleaseHandle()) return false;  
			
			// ���������� ��������� ������� 
			return ::NCryptFreeObject(Value) == ERROR_SUCCESS;
		} 
		// ��������� ���������� ���������
		public: property NCRYPT_PROV_HANDLE Value 
		{ 
			// ��������� ���������� ���������
			NCRYPT_PROV_HANDLE get() { return (NCRYPT_PROV_HANDLE)handle.ToPointer(); }
		}   
		// ���������� ��� ����������
		public: property String^ Name { String^ get() 
		{ 
			// ���������� ��� ����������
			return GetString(NCRYPT_NAME_PROPERTY, 0);  
		}} 
		// �������� ��������
		public: virtual DWORD GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// �������� ��������
		public: virtual DWORD GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 
		// ���������� ��������
		public: virtual void SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags) override; 

		// ����������� ���������
		public: array<String^>^ EnumerateAlgorithms(DWORD type, DWORD flags); 
		// ����������� �����
		public: array<String^>^ EnumerateKeys(String^ scope, DWORD flags); 

		// ������ �������� ���� ������
		public: NKeyHandle^ StartCreateKey(String^ name, String^ algID, 
			DWORD keyType, DWORD flags
		);
		// �������� ���� ������
		public: NKeyHandle^ OpenKey(String^ name, DWORD keyType, DWORD flags);
		// ������� ���� ������
		public: static void DeleteKey(NKeyHandle^ hKeyPair, DWORD flags);

		// ������ ������������� ���� ������
		public: NKeyHandle^ StartImportKeyPair(String^ name, 
            NKeyHandle^ hImportKey, String^ blobType, IntPtr ptrBlob, 
            DWORD cbBlob, DWORD flags
		);
		// ������������� �������� ����
		public: NKeyHandle^ ImportPublicKey(
            String^ blobType, IntPtr ptrBlob, DWORD cbBlob, DWORD flags
        );  
	}; 
}}}

#pragma once
#include "Handle.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	///////////////////////////////////////////////////////////////////////
	// �������� ��������� ������������
	///////////////////////////////////////////////////////////////////////
	public ref class Mac abstract : CAPI::Mac
	{
		private: Using<BProviderHandle^> hProvider;	// ����������������� �������� 
		private: Using<BHashHandle^>	 hHash;		// �������� ���������� ������������ 
		
		// �����������
		protected: Mac(String^ provider, String^ name, DWORD flags) 

			// ��������� ��������� ���������� ���������
			: hProvider(gcnew BProviderHandle(provider, name, flags)) {}

		// ������ ������������ � ������
		public:	virtual property int MacSize  
		{ 
			// ������ ������������ � ������
			int get() override { return hProvider.Get()->GetLong(BCRYPT_HASH_LENGTH, 0); } 
		}
		// ���������������� ��������
		public: virtual void Init(ISecretKey^ key) override; 
		// ������������ ������
		public: virtual void Update(array<BYTE>^ data, int dataOff, int dataLen) override; 
		// �������� ������������
		public: virtual int Finish(array<BYTE>^ buffer, int bufferOff) override; 
	};
}}}


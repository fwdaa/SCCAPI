#pragma once
#include "Handle.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	///////////////////////////////////////////////////////////////////////
	// �������� �����������
	///////////////////////////////////////////////////////////////////////
	public ref class Hash abstract : CAPI::Hash
	{
		private: String^				 name;		// ��� ���������
		private: Using<BProviderHandle^> hProvider;	// ����������������� �������� 
		private: Using<BHashHandle^>	 hHash;		// �������� ����������� 
		
		// �����������
		protected: Hash(String^ provider, String^ name, DWORD flags) 

			// ��������� ��������� ���������� ���������
			: hProvider(gcnew BProviderHandle(provider, name, flags)) {	this->name = name; }

		// ��� ���������
		public: property String^ Name {String^ get() { return name; } }

		// ������ ���-�������� � ������
		public:	virtual property int HashSize  
		{ 
			// ������ ���-�������� � ������
			int get() override { return hProvider.Get()->GetLong(BCRYPT_HASH_LENGTH, 0); } 
		}
		// ���������������� ��������
		public: virtual void Init() override;  
		// ������������ ������
		public: virtual void Update(array<BYTE>^ data, int dataOff, int dataLen) override; 
		// �������� ���-��������
		public: virtual int Finish(array<BYTE>^ buffer, int bufferOff) override; 
	};
}}}
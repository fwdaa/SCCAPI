#pragma once
#include "Applet.h"
#include "Family.h"

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU
{
    ///////////////////////////////////////////////////////////////////////////
    // ��������� ��������
    ///////////////////////////////////////////////////////////////////////////
	public ref class ProviderImpl : IProviderImpl
	{	
		// ������������ ��������� �����-����
		private: ITokenFamily^ etFamily; private: ITokenFamily^ jcFamily;

		// �����������
		public: ProviderImpl()
		{
			// ������� �������������� ���������
			etFamily = gcnew ETFamily(); jcFamily = gcnew JCFamily(); 
		}
		// ��� ����������
		public: virtual property String^ Name 
		{ 
			// ��� ����������
			String^ get() { return "Aladdin Applet Provider"; } 
		}
        // ����������� �������
  		public: virtual array<String^>^ EnumerateApplets(SCard::Card^ store); 
        // ������� ������
        public: virtual Applet^ OpenApplet(SCard::Card^ store, String^ name); 
	};
}}}}

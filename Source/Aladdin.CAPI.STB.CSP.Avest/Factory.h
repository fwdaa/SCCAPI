#pragma once

#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace STB { namespace Avest { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// ������� �������� ����������
	///////////////////////////////////////////////////////////////////////////
	public ref class Factory : CAPI::Factory
	{
		// ����������������� ����������
		private: Dictionary<String^, CAPI::Provider^>^ providers;  
	
		// �����������
		public: Factory()
		{
			// ������� ������ �����������
			providers = gcnew Dictionary<String^, CAPI::Provider^>();
			
			// ������� ����������
			Provider^ providerFull = gcnew ProviderFull(this); 
			Provider^ providerPro  = gcnew ProviderPro (this); 

			// �������� ��������� � ������
			providers->Add(providerFull->Name, providerFull);
			providers->Add(providerPro ->Name, providerPro );
		}
		// ������� �������������� ����������
		public: virtual property Dictionary<String^, CAPI::Provider^>^ Providers 
		{ 
			// ������� �������������� ����������
			Dictionary<String^, CAPI::Provider^>^ get() override { return providers; } 
		} 
		// ������� ������� ������
		public: virtual IKeyFactory^ GetKeyFactory(
			ASN1::ISO::AlgorithmIdentifier^ parameters) override; 

		// ������� �������� ��������� ������
		public: virtual IKeyPairGenerator^ CreateGenerator(
			IKeyFactory^ keyFactory, IRand^ rand) override; 

		// ������� �������� ��� ����������
		public: virtual IAlgorithm^ CreateAlgorithm(
			ASN1::ISO::AlgorithmIdentifier^ parameters, Type^ type, Object^ context) override;
	};
}}}}}
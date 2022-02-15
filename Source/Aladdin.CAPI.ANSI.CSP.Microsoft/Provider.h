#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер 
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider abstract : CAPI::CSP::Provider
	{
		// конструктор
		protected: Provider(DWORD type, String^ name, bool sspi) : CAPI::CSP::Provider(type, name, sspi) {} 

		// получить алгоритмы по умолчанию
		public: virtual CAPI::Culture^ GetCulture(SecurityStore^ scope, String^ keyOID) override
        {
			// указать фабрику алгоритмов
			Using<CAPI::Factory^> factory(gcnew ANSI::Factory()); 

			// получить алгоритмы по умолчанию
			return factory.Get()->GetCulture(scope, keyOID); 
		}
		// получить алгоритмы по умолчанию
		public: virtual PBE::PBECulture^ GetCulture(PBE::PBEParameters^ parameters, String^ keyOID) override
        {
			// указать фабрику алгоритмов
			Using<CAPI::Factory^> factory(gcnew ANSI::Factory()); 

			// получить алгоритмы по умолчанию
			return factory.Get()->GetCulture(parameters, keyOID); 
		}
		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, 
			ASN1::ISO::AlgorithmIdentifier^ parameters, System::Type^ type) override
		{
			// вызвать базовую функцию
			return ANSI::Factory::RedirectAlgorithm(outer, scope, parameters, type); 
		}
	}; 
}}}}}

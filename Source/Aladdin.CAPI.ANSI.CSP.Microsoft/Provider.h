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

		// создать алгоритм для параметров
		public protected: virtual IAlgorithm^ CreateAlgorithm(
			Factory^ outer, SecurityStore^ scope, String^ oid, 
			ASN1::IEncodable^ parameters, System::Type^ type) override
		{
			// вызвать базовую функцию
			return ANSI::Factory::RedirectAlgorithm(outer, scope, oid, parameters, type); 
		}
        // получить идентификатор ключа
		public: virtual String^ ConvertKeyName(String^ name) override
        { 
            // получить идентификатор ключа
            return Aliases::ConvertKeyName(name); 
        } 
        // получить идентификатор алгоритма
		public: String^ ConvertAlgorithmName(String^ name) override
        { 
            // получить идентификатор ключа
            return Aliases::ConvertAlgorithmName(name); 
        } 
	}; 
}}}}}

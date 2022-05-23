#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar { namespace GOST34310
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyPairGenerator : CAPI::CSP::KeyPairGenerator
	{
		// конструктор
		public: KeyPairGenerator(CAPI::CSP::Provider^ provider, 
			SecurityObject^ scope, IRand^ rand, INamedParameters^ parameters)

			// сохранить переданные параметры
			: CAPI::CSP::KeyPairGenerator(provider, scope, rand, parameters) {}

		// сгенерировать пару ключей
		protected: virtual CAPI::CSP::KeyHandle^ Generate(
			CAPI::CSP::Container^ container, 
            String^ keyOID, DWORD keyType, DWORD keyFlags) override; 
	};
}}}}}

#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar { namespace RSA
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyPairGenerator : CAPI::CSP::KeyPairGenerator
	{
		// конструктор
		public: KeyPairGenerator(CAPI::CSP::Provider^ provider, 
			SecurityObject^ scope, IRand^ rand, ANSI::RSA::IParameters^ parameters)

			// сохранить переданные параметры
			: CAPI::CSP::KeyPairGenerator(provider, scope, rand, parameters) 
		{
			// проверить значение экспоненты
			if (parameters->PublicExponent != Math::BigInteger::ValueOf(0x10001L)) 
			{
				// при ошибке выбросить исключение
				throw gcnew NotSupportedException(); 
			}
		}
		// сгенерировать пару ключей
		protected: virtual CAPI::CSP::KeyHandle^ Generate(
			CAPI::CSP::Container^ container, 
			String^ keyOID, DWORD keyType, DWORD keyFlags) override;  
	};
}}}}}

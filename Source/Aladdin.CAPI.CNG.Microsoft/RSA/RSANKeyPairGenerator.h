#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace RSA
{
	//////////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей
	//////////////////////////////////////////////////////////////////////////////
    public ref class NKeyPairGenerator : CAPI::CNG::NKeyPairGenerator
    {
		// конструктор
		public: NKeyPairGenerator(CAPI::CNG::NProvider^ provider, 
			SecurityObject^ scope, IRand^ rand, ANSI::RSA::IParameters^ parameters)

			// сохранить переданные параметры
			: CAPI::CNG::NKeyPairGenerator(provider, scope, rand, parameters) 
		{
			// проверить значение экспоненты
			if (parameters->PublicExponent != Math::BigInteger::ValueOf(0x10001L))
			{
				// при ошибке выбросить исключение
				throw gcnew NotSupportedException(); 
			}
		}
		// сгенерировать пару ключей
		protected: virtual CAPI::CNG::NKeyHandle^ Generate(
            CAPI::CNG::Container^ container, 
            String^ keyOID, DWORD keyType, BOOL exportable) override; 
    };
}}}}}

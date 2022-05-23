#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace X957
{
	//////////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей
	//////////////////////////////////////////////////////////////////////////////
    public ref class NKeyPairGenerator : CAPI::CNG::NKeyPairGenerator
    {
		// конструктор
		public: NKeyPairGenerator(CAPI::CNG::NProvider^ provider, 
			SecurityObject^ scope, IRand^ rand, ANSI::X957::IParameters^ parameters)

			// сохранить переданные параметры
			: CAPI::CNG::NKeyPairGenerator(provider, scope, rand, parameters) {}

		// сгенерировать пару ключей
		protected: virtual CAPI::CNG::NKeyHandle^ Generate(
            CAPI::CNG::Container^ container, 
            String^ keyOID, DWORD keyType, BOOL exportable) override; 
    };
}}}}}

#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace X942
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей DH
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyPairGenerator : CAPI::CSP::KeyPairGenerator
	{
		// способ кодирования чисел
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian; 

		// конструктор
		public: KeyPairGenerator(CAPI::CSP::Provider^ provider, 
			SecurityObject^ scope, IRand^ rand, CAPI::ANSI::X942::IParameters^ parameters) 

			// сохранить переданные параметры
			: CAPI::CSP::KeyPairGenerator(provider, scope, rand, parameters) {} 

		// сгенерировать пару ключей
		protected: virtual CAPI::CSP::KeyHandle^ Generate(
			CAPI::CSP::Container^ container, 
			String^ keyOID, DWORD keyType, DWORD keyFlags) override; 
	};
}}}}}

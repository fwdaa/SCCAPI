#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace X957
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей DSA
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyPairGenerator : CAPI::CSP::KeyPairGenerator
	{
		// способ кодирования чисел
		protected: static const Math::Endian Endian = Math::Endian::LittleEndian; 

		// конструктор
		public: KeyPairGenerator(CAPI::CSP::Provider^ provider, 
			SecurityObject^ scope, IRand^ rand, CAPI::ANSI::X957::IParameters^ parameters) 

			// сохранить переданные параметры
			: CAPI::CSP::KeyPairGenerator(provider, scope, rand, parameters) {} 

		// сгенерировать пару ключей
		protected: virtual CAPI::CSP::KeyHandle^ Generate(
			CAPI::CSP::Container^ container, 
			String^ keyOID, DWORD keyType, DWORD keyFlags) override; 
	};
}}}}}}

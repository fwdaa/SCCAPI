#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace X942
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей
	///////////////////////////////////////////////////////////////////////////
	public ref class BKeyPairGenerator : CAPI::CNG::BKeyPairGenerator
	{
		// конструктор
		public: BKeyPairGenerator(CAPI::Factory^ factory, SecurityObject^ scope, 
			IRand^ rand, String^ provider, ANSI::X942::IParameters^ parameters) 
			
			// сохранить переданные параметры
			: CAPI::CNG::BKeyPairGenerator(factory, scope, rand, provider, BCRYPT_DH_ALGORITHM, 0) 
		 
			// сохранить переданные параметры
			{ this->parameters = parameters; } private: ANSI::X942::IParameters^ parameters; 

		// сгенерировать пару ключей
		public: virtual KeyPair^ Generate(String^ keyOID) override; 
	};
}}}}}


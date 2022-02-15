#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace RSA
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей
	///////////////////////////////////////////////////////////////////////////
	public ref class BKeyPairGenerator : CAPI::CNG::BKeyPairGenerator
	{
		// параметры генерации
		private: ANSI::RSA::IParameters^ parameters; 

		// конструктор
		public: BKeyPairGenerator(CAPI::Factory^ factory, SecurityObject^ scope, 
			IRand^ rand, String^ provider, ANSI::RSA::IParameters^ parameters) 
			
			// сохранить переданные параметры
			: CAPI::CNG::BKeyPairGenerator(factory, scope, rand, provider, BCRYPT_RSA_ALGORITHM, 0) 
		 { 
			// проверить значение экспоненты
			if (parameters->PublicExponent != Math::BigInteger::ValueOf(0x10001L))
			{
				// при ошибке выбросить исключение
				throw gcnew NotSupportedException(); 
			}
			// сохранить переданные параметры
			this->parameters = parameters; 
		} 
		// сгенерировать пару ключей
		public: virtual KeyPair^ Generate(String^ keyOID) override; 
	};
}}}}}}

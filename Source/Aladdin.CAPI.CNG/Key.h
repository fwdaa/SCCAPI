#pragma once
#include "Handle.h"

namespace Aladdin { namespace CAPI { namespace CNG 
{
	ref class NProvider; 

	///////////////////////////////////////////////////////////////////////////
	// Личный ключ асимметричного алгоритма
	///////////////////////////////////////////////////////////////////////////
	public ref class NPrivateKey : CAPI::PrivateKey
	{
		// параметры и описатель личного ключа
		private: IParameters^ parameters; private: NKeyHandle^ hPrivateKey;

		// конструктор 
		public: NPrivateKey(NProvider^ provider, SecurityObject^ scope, 
			IPublicKey^ publicKey, NKeyHandle^ hPrivateKey
		); 
		// деструктор
        public: virtual ~NPrivateKey() { CNG::Handle::Release(hPrivateKey); }

		// параметры ключа
		public: virtual property IParameters^ Parameters 
		{ 
			// параметры ключа
			IParameters^ get() override { return parameters; }  
		}
		// описатель ключа
		public protected: property NKeyHandle^ Handle 
		{ 
			// описатель ключа
			NKeyHandle^ get() { return hPrivateKey; }
		} 
        // экспортировать ключ
        protected: array<BYTE>^ Export(NKeyHandle^ hExportKey, String^ blobType, DWORD flags); 
	};
}}}
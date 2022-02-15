#pragma once

#include "Handle.h"

namespace Aladdin { namespace CSP 
{
	ref class Container; 

	///////////////////////////////////////////////////////////////////////////
	// Личный ключ асимметричного алгоритма
	///////////////////////////////////////////////////////////////////////////
	public ref class PrivateKey : CAPI::IPrivateKey
	{
		private: CAPI::IKeyFactory^	keyFactory;		// фабрика ключей
		private: CSP::Container^	container;		// контейнер ключа
		private: CAPI::KeyUsage		keyUsage;		// тип ключа
 
		// конструктор
		public: PrivateKey(CAPI::IKeyFactory^ keyFactory, CSP::Container^ container, 
			CAPI::KeyUsage keyUsage) 
		{
			this->keyFactory	= keyFactory;		// фабрика алгоритмов
			this->container		= container;		// контейнер ключа
			this->keyUsage		= keyUsage;			// тип ключа
		}
		public: virtual ~PrivateKey() {}

		// фабрика алгоритмов
		public: virtual property CAPI::IKeyFactory^ KeyFactory 
		{ 
			// вернуть фабрику алгоритмов
			CAPI::IKeyFactory^ get() { return keyFactory; }
		}
		// контейнер и тип ключа 
		public: property CSP::Container^ Container { CSP::Container^ get() { return container; }} 
		public: property CAPI::KeyUsage  KeyUsage  { CAPI::KeyUsage  get() { return keyUsage;  }} 
	};
	///////////////////////////////////////////////////////////////////////////
	// Эфемерный личный ключ асимметричного алгоритма
	///////////////////////////////////////////////////////////////////////////
	public ref class EphemeralPrivateKey : CAPI::IPrivateKey
	{
		private: CAPI::IKeyFactory^	keyFactory;		// фабрика ключей
		private: KeyPtr				hPrivateKey;	// описатель ключа

		// конструктор 
		public: EphemeralPrivateKey(CAPI::IKeyFactory^ keyFactory, KeyPtr hKey) : hPrivateKey(hKey) 
		{ 
			this->keyFactory = keyFactory;		// фабрика алгоритмов
		}  
		// закрыть описатель личного ключа
		public: virtual ~EphemeralPrivateKey() { hPrivateKey.Clear(); }

		// фабрика алгоритмов
		public: virtual property CAPI::IKeyFactory^ KeyFactory 
		{ 
			// вернуть фабрику алaQгоритмов
			CAPI::IKeyFactory^ get() { return keyFactory; }
		}
		// описатель личного ключа
		public: property KeyPtr Handle { KeyPtr get() { return hPrivateKey; } } 
	};
}}
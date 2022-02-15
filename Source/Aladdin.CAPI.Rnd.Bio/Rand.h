#pragma once

namespace Aladdin { namespace CAPI { namespace Rnd { namespace Bio
{
	///////////////////////////////////////////////////////////////////////
	// Фабрика создания генераторов случайных данных (режим совместимости)
	///////////////////////////////////////////////////////////////////////
	public ref class LegacyRandFactory : RefObject, IRandFactory
	{
		// создать генератор случайных данных
		public: virtual IRand^ CreateRand(Object^ window);  
	};
	///////////////////////////////////////////////////////////////////////
	// Фабрика создания генераторов случайных данных (для сертификации)
	///////////////////////////////////////////////////////////////////////
	public ref class RandFactory : RefObject, IRandFactory
	{
		// конструктор
		public: RandFactory(bool anyChar) { this->anyChar = anyChar; } 
		// конструктор
		public: RandFactory() { anyChar = false; } private: bool anyChar; 

		// создать генератор случайных данных
		public: virtual IRand^ CreateRand(Object^ window);  
	};
}}}}

#pragma once
#include "Applet.h"
#include "Family.h"

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU
{
    ///////////////////////////////////////////////////////////////////////////
    // Провайдер апплетов
    ///////////////////////////////////////////////////////////////////////////
	public ref class ProviderImpl : IProviderImpl
	{	
		// используемые семейства смарт-карт
		private: ITokenFamily^ etFamily; private: ITokenFamily^ jcFamily;

		// конструктор
		public: ProviderImpl()
		{
			// указать поддерживаемые семейства
			etFamily = gcnew ETFamily(); jcFamily = gcnew JCFamily(); 
		}
		// имя провайдера
		public: virtual property String^ Name 
		{ 
			// имя провайдера
			String^ get() { return "Aladdin Applet Provider"; } 
		}
        // перечислить апплеты
  		public: virtual array<String^>^ EnumerateApplets(SCard::Card^ store); 
        // открыть апплет
        public: virtual Applet^ OpenApplet(SCard::Card^ store, String^ name); 
	};
}}}}

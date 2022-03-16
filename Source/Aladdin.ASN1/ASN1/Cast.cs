﻿using System;

namespace Aladdin.ASN1
{
	///////////////////////////////////////////////////////////////////////
	// Атрибуты поля в структуре
	///////////////////////////////////////////////////////////////////////
	[Flags]
	public enum Cast { 
		N	= 0,	// отсутствие атрибутов
		E	= 1,	// явное приведение типа
		O	= 2,	// необязательное поле
		EO	= 3,	// явное приведение типа + необязательное поле
	}; 
}

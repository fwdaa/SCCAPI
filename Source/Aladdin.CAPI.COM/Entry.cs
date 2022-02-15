using System;
using System.Globalization;

namespace Aladdin.CAPI.COM
{
	///////////////////////////////////////////////////////////////////////////
	// Взаимодействие с неуправляемым кодом
	///////////////////////////////////////////////////////////////////////////
	public sealed partial class Entry : IEntry
	{
		// создать фабрику алгоритмов
		public IFactory CreateFactory(uint lcid, string fileName) 
		{ 
            // создать фабрику алгоритмов
            return new Factory(new CultureInfo((int)lcid), fileName); 
		}
	}
}

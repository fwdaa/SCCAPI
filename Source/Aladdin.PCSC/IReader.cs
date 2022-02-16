﻿namespace Aladdin.PCSC
{
    ///////////////////////////////////////////////////////////////////////////
	// Считыватель смарт-карт
	///////////////////////////////////////////////////////////////////////////
    public interface IReader
	{
		// имя и состояние считывателя
		string Name { get; } ReaderState GetState(); 

        // смарт-карта считывателя
        ICard OpenCard(); 
	}
}
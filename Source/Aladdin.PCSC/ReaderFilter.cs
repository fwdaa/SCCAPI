﻿namespace Aladdin.PCSC
{
	///////////////////////////////////////////////////////////////////////
    // Функция обратного вызова при перечислении считывателей
	///////////////////////////////////////////////////////////////////////
    public delegate bool ReaderFilter(
        Reader reader, ReaderSession session, object userData
    );  
}

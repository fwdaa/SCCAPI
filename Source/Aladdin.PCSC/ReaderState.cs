﻿namespace Aladdin.PCSC
{
    ///////////////////////////////////////////////////////////////////////////
    // Состояние считывателя
    ///////////////////////////////////////////////////////////////////////////
    public enum ReaderState { 
        Unknown     = 0, // неизвестное имя считывателя
        Unavailable = 1, // неизвестное состояние считывателя
        Empty       = 2, // отсутствует смарт-карта в считывателе
        Card        = 3  // присутствует смарт-карта в считывателе
    }; 
}
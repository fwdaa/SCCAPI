﻿namespace Aladdin.CAPI.Bio.BSAPI
{
	///////////////////////////////////////////////////////////////////////
	// Типы уведомлений функции обратного вызова
	///////////////////////////////////////////////////////////////////////
    public enum NotificationEvent : int {		
        Idle			= 0x00000000,	// отсутствие активности
        ProcessBegin	= 0x11000000,	// начало нового этапа
        ProcessEnd		= 0x12000000,	// завершение текущего этапа
        ProcessSuspend	= 0x13000000,	// остановка текущего этапа
        ProcessResume	= 0x14000000,	// возобновление текущего этапа
        ProcessProgress	= 0x15000000,	// прогресс текущего этапа
        ProcessSuccess	= 0x16000000,	// корректное завершение текущего этапа
        ProcessFailure	= 0x17000000,	// ошибочное завершение текущего этапа
        PromptScan		= 0x21000000,	// вывод сообщения о необходимости приложения пальца
        PromptTouch		= 0x22000000,	// вывод сообщения о необходимости прикосновения к сенсору
        PromptKeep		= 0x23000000,	// вывод сообщения о необходимости удержания пальца на сенсоре
        PromptLift		= 0x24000000,	// вывод сообщения о необходимости снятия пальца с сенсора
        PromptClean		= 0x25000000,	// вывод сообщения о необходимости очистки сенсора
        NavigateChange	= 0x41000000,	// уведомление о событии навигации (проведение пальцем по сенсору)
        NavigateClick	= 0x42000000,	// уведомление о событии нажатии на сенсор при навигации
        DialogShow		= 0x51000000,	// уведомление о необходимости отображения диалога
        DialogHide		= 0x52000000,	// уведомление о необходимости закрытия диалога
    };
}

using System;

namespace Aladdin.CAPI.Bio.BSAPI
{
	///////////////////////////////////////////////////////////////////////
    // Интерфейс обработчика уведомлений
	///////////////////////////////////////////////////////////////////////
	public interface INotificationHandler 
	{
		// обработка отсутствия активности
		void OnIdle(ReaderSession connection, int opID, Process process, object context);

		// начало нового этапа
		void OnProcessBegin(ReaderSession connection, int opID, Process process, object context);

		// прогресс этапа
		void OnProcessProgress(ReaderSession connection, int opID, Process process, int percentage, object context);

		// остановка этапа
		void OnProcessSuspend(ReaderSession connection, int opID, Process process, object context);

		// возобновление этапа
		void OnProcessResume(ReaderSession connection, int opID, Process process, object context);

		// успешное завершение этапа
		void OnProcessSuccess(ReaderSession connection, int opID, Process process, byte[] bitmap, IntPtr template, object context);   

		// ошибочное завершение этапа
		void OnProcessFailure(ReaderSession connection, int opID, Process process, object context);   

		// завершение этапа
		void OnProcessEnd(ReaderSession connection, int opID, Process process, object context);

		// необходимость вывода сообщения
		void OnPrompt(ReaderSession connection, int opID, Process process, NotificationEvent type, object context);   

		// низкое качество отпечатка
		void OnLowQuality(ReaderSession connection, int opID, Process process, ImageQuality quality, object context); 
	}
}

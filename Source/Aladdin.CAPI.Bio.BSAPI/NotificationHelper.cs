using System;
using System.Security;
using System.Runtime.InteropServices;

namespace Aladdin.CAPI.Bio.BSAPI
{
	///////////////////////////////////////////////////////////////////////
	// Обработчик при выполнении биометрической аутентификации
	///////////////////////////////////////////////////////////////////////
    internal class NotificationHelper
    {
        // соединение и используемый обработчик
        private ReaderSession connection; private INotificationHandler handler; 

        // используемый процесс и дополнительные данные
        private Process process; private Object obj; 

        // конструктор
        public NotificationHelper(ReaderSession connection, INotificationHandler handler, object obj) 
        { 
            // сохранить переданные параметры
            this.connection = connection; this.handler = handler; 
            
            // указать начальные условия
            this.obj = obj; process = null; 
        }
        // реализация функции обратного вызова
        [SecuritySafeCritical]
        public void Invoke(int opID, Int32 msgID, IntPtr msgData)
        {
			// проверить наличие обработчика
			if (handler == null) return; 

            // при низком качестве изображения
            if ((int)ImageQuality.Low <= msgID && msgID <= (int)ImageQuality.LowJoint)
            {
                // выполнить обработчик
                handler.OnLowQuality(connection, opID, process, (ImageQuality)msgID, obj); 
            }
            else switch ((NotificationEvent)msgID)
            { 
            // при отсутствии активности
            case NotificationEvent.Idle:
            {
                // выполнить обработчик
                handler.OnIdle(connection, opID, process, obj); break; 
            }
            // при начале этапа
            case NotificationEvent.ProcessBegin:
            {
                // создать описание внутреннего этапа
                process = new Process(process, (ProcessID)Marshal.ReadInt32(msgData)); 

                // выполнить обработчик
                handler.OnProcessBegin(connection, opID, process, obj); break; 
            }
            // при завершении этапа
            case NotificationEvent.ProcessEnd:
            {
                // выполнить обработчик
                handler.OnProcessEnd(connection, opID, process, obj); 

                // перейти на внешний этап
                process = process.Parent; break; 
            }
            // при остановке этапа
            case NotificationEvent.ProcessSuspend:
            {
                // выполнить обработчик
                handler.OnProcessSuspend(connection, opID, process, obj); break; 
            }
            // при возобновлении этапа
            case NotificationEvent.ProcessResume: 
            {
                // выполнить обработчик
                handler.OnProcessResume(connection, opID, process, obj); break; 
            }
            // при прогрессе этапа
            case NotificationEvent.ProcessProgress: 
            {
		        // перейти на описание прогресса операции
		        msgData = new IntPtr(msgData.ToInt64() + sizeof(Int32));

                // прочитать прогресс операции
		        Int32 percentage = Marshal.ReadInt32(msgData);

                // выполнить обработчик
                handler.OnProcessProgress(connection, opID, process, percentage, obj); break; 
            }
            // при ошибочном завершении этапа
            case NotificationEvent.ProcessFailure:
            {
                // выполнить обработчик
                handler.OnProcessFailure(connection, opID, process, obj); break; 
            }
            // при успешном завершении этапа
            case NotificationEvent.ProcessSuccess: 
            {
		        // перейти на описание изображения
		        msgData = new IntPtr(msgData.ToInt64() + IntPtr.Size);

                // прочитать указатель на изображение
                IntPtr ptrImage = Marshal.ReadIntPtr(msgData); 

                // при наличии изображения
                byte[] image = Bitmap.Read(ptrImage); 

                // перейти на описание шаблона
		        msgData = new IntPtr(msgData.ToInt64() + IntPtr.Size);

                // прочитать указатель на шаблон
                IntPtr ptrTemplate = Marshal.ReadIntPtr(msgData); 

                // выполнить обработчик
                handler.OnProcessSuccess(connection, opID, process, image, ptrTemplate, obj); break; 
            }
            // при передаче сообщения
            case NotificationEvent.PromptScan : case NotificationEvent.PromptTouch: 
            case NotificationEvent.PromptKeep : case NotificationEvent.PromptLift : 
            case NotificationEvent.PromptClean: 
            {
                // указать тип события 
                NotificationEvent data = (NotificationEvent)msgID; 

                // выполнить обработчик
                handler.OnPrompt(connection, opID, process, data, obj); break; 
            }
            // при передаче сообщения
            case NotificationEvent.DialogShow: case NotificationEvent.DialogHide: 
            {
                // указать тип события 
                NotificationEvent data = (NotificationEvent)msgID; 

                // выполнить обработчик
                handler.OnPrompt(connection, opID, process, data, obj); break; 
            }}
        }
    }
}

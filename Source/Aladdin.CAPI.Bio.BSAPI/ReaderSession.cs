using System;
using System.Security;
using System.Security.Permissions;
using System.IO;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace Aladdin.CAPI.Bio.BSAPI
{
	///////////////////////////////////////////////////////////////////////
	// Соединение с биометрическим устройством
	///////////////////////////////////////////////////////////////////////
	public sealed class ReaderSession : RefObject
	{
		// провайдер и описатель соединения
		private Provider provider; private uint handle; 

		// конструктор
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
		public ReaderSession(Provider provider, string DsnSubString)
		{
		    // создать соединение с биометрическим устройством
		    Int32 status = NativeMethods.ABSOpen(DsnSubString, out handle); 

		    // проверить отсутствие ошибок
		    if (status != 0) throw new Exception(status);

            // сохранить переданные параметры
            this.provider = RefObject.AddRef(provider); 
		}
		// освободить выделенные ресурсы
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
		protected override void OnDispose() 
        { 
		    // освободить выделенные ресурсы
            RefObject.Release(provider); NativeMethods.ABSClose(handle); base.OnDispose();
        }
        // используемый провайдер
        public Provider Provider { get { return provider; }}

		// перечислить поддерживаемые форматы изображения
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
		public ImageFormat[] ListImageFormats()
		{
		    // указать тип структуры
		    Type itemType = typeof(ImageFormat); IntPtr pFormatList;   

		    // определить размер структуры
		    Int32 itemSize = Marshal.SizeOf(itemType); UInt32 formatCount;

		    // перечислить поддерживаемые форматы изображения
		    Int32 status = NativeMethods.ABSListImageFormats(
                handle, out formatCount, out pFormatList, 0
            ); 
		    // проверить отсутствие ошибок
		    if (status != 0) throw new Exception(status); IntPtr pFormat = pFormatList; 
        
		    // выделить список структур
		    ImageFormat[] listFormats = new ImageFormat[formatCount]; 

		    // для всех форматов
		    for (int i = 0; i < formatCount; i++)
		    {
			    // извлечь описание структуры
			    listFormats[i] = (ImageFormat)Marshal.PtrToStructure(pFormat, itemType); 

			    // перейти на следующую структуру
			    pFormat = new IntPtr(pFormat.ToInt64() + itemSize); 
		    }
		    // освободить выделенную память
		    NativeMethods.ABSFree(pFormatList); return listFormats; 
		}
        // захватить изображение
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public ImageInfo GrabImage(
            Int32                opID,          // уникальный идентификатор операции
            ImageTarget          target,        // назначение снимаемого отпечатка
            ImageFormat			 format,        // формат изображения
            Int32                timeout,       // тайм-аут ожидания активности в миллисекундах
            NotificationMode     flags,         // режим получения уведомлений
		    INotificationHandler handler,       // обработчик уведомлений   
            Object               context        // дополнительные данные для обработчика
	    ) {
            // создать специальный обработчик
            NotificationHelper notificationHelper = new NotificationHelper(this, handler, context); 

            // создать параметры генерации
            NativeMethods.OPERATION operation; operation.OperationID = (uint)opID; 

            // указать параметры генерации
            operation.Timeout = timeout; operation.Callback = GrabImageCallback; operation.Flags = flags; 

	        // заблокировать делегат в памяти
	        GCHandle lockHandler = GCHandle.Alloc(notificationHelper); 
            try {             
                // указать параметры для функции обратного вызова
                operation.Context = GCHandle.ToIntPtr(lockHandler); 

                // выделить место для выходных параметров
                NativeMethods.SWIPE_INFO swipeInfo; IntPtr ptrImage; 

                // указать начальные условия
                NativeMethods.Purpose dwPurpose = NativeMethods.Purpose.Undefined; 
                switch (target)
                {
                // указать назначение отпечатка
                case ImageTarget.Match : dwPurpose = NativeMethods.Purpose.Verify; break; 
                case ImageTarget.Enroll: dwPurpose = NativeMethods.Purpose.Enroll; break; 
                }
                // выполнить снятие отпечатка
                Int32 status = NativeMethods.ABSGrabImage(handle, ref operation, 
                    dwPurpose, ref format, out ptrImage, out swipeInfo, IntPtr.Zero, 0
                ); 
		        // проверить отсутствие ошибок
		        if (status != 0) throw new Exception(status); 

                // прочитать Bitmap-изображение
                ImageInfo info; info.Bitmap = Bitmap.Read(ptrImage);
                
                // вернуть информацию отпечатка
                info.ReconstructionScore = swipeInfo.ReconstructionScore; 
                info.ImageScore          = swipeInfo.ImageScore; 
                info.BackgroundColor     = swipeInfo.BackgroundColor; 
                info.Quality             = swipeInfo.Quality; 
                
                return info; 
            }
            // освободить заблокированный объект
            finally { lockHandler.Free(); } 
        } 
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        private static void GrabImageCallback(ref NativeMethods.OPERATION op, Int32 msgID, IntPtr msgData)
        {
            // указать тип данных
            Type handlerType = typeof(NotificationHelper); 

            // преобразовать тип дополнительных данных
            NotificationHelper obj = (NotificationHelper)Marshal.PtrToStructure(op.Context, handlerType); 

            // выполнить обработчик
            obj.Invoke((int)op.OperationID, msgID, msgData); 
        }
        // запустить процесс захвата отпечатка
        public Remoting.RemoteClientControl BeginCapture(ImageTarget target, 
            Predicate<Image> check, TimeSpan timeout, Remoting.IBackgroundHandler handler)
        {
            // прочитать поддерживаемые форматы изображений
            ImageFormat[] formats = ListImageFormats(); if (formats.Length == 0) throw new IOException();

            // указать способ захвата отпечатка
            using (CaptureClient client = new CaptureClient(this, target, formats[0], check, timeout))
            {
                // запустить процесс захвата отпечатка
                return client.Start(handler); 
            }
        }
		// отменить выполняемую операцию
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
		public void CancelOperation(int opID)
		{
		    // отменить выполняемую операцию
		    Int32 status = NativeMethods.ABSCancelOperation(handle, (uint)opID); 

		    // проверить отсутствие ошибок
		    if (status != 0) throw new Exception(status);  
		}
	}
}

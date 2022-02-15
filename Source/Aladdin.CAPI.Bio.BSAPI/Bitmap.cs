using System;
using System.Security;
using System.Security.Permissions;
using System.Runtime.InteropServices;

namespace Aladdin.CAPI.Bio.BSAPI
{
    internal static class Bitmap
    {
        ///////////////////////////////////////////////////////////////////////
        // Заголовок .BMP-файла 
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack=1)]
        private struct BITMAPFILEHEADER {
            public UInt16 bfType;           // тип изображения = 0x4D42
            public UInt32 bfSize;           // общий размер файла
            public UInt16 bfReserved1;      // зарезервировано
            public UInt16 bfReserved2;      // зарезервировано
            public UInt32 bfOffBits;        // смещение массива точек от начала файла
        };
        ///////////////////////////////////////////////////////////////////////
        // Описание .BMP-изображения
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack=1)]
        private struct BITMAPINFOHEADER {
            public UInt32 biSize;           // размер описания
            public Int32  biWidth;          // число точек по горизонтали
            public Int32  biHeight;         // число точек по вертикали
            public UInt16 biPlanes;         // число плоскостей (всегда 1)
            public UInt16 biBitCount;       // число бит на пиксел
            public UInt32 biCompression;    // способ хранения пикселов (RGB = 0)
            public UInt32 biSizeImage;      // 
            public Int32  biXPelsPerMeter;  // число пикселов на метр по горизонтали
            public Int32  biYPelsPerMeter;  // число пикселов на метр по вертикали  
            public UInt32 biClrUsed;        // размер таблицы цветов
            public UInt32 biClrImportant;   // число используемых цветов с начала таблицы
        };
        ///////////////////////////////////////////////////////////////////////
        // Описание элемента таблицы цветов
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct RGBQUAD {            // элемент таблицы цветов
            public Byte rgbBlue;            // синяя составляющая
            public Byte rgbGreen;           // зеленая составляющая
            public Byte rgbRed;             // красная составляющая
            public Byte rgbAlpha;           // прозрачность цвета
        };
        ///////////////////////////////////////////////////////////////////////
        // Создать .BMP-изображение
        ///////////////////////////////////////////////////////////////////////
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public static byte[] Create(NativeMethods.IMAGE_HEADER header, byte[] points)
        {
            // выделить память для структур
            BITMAPFILEHEADER fileHeader; BITMAPINFOHEADER imageHeader; fileHeader.bfType = 0x4D42; 

            // указать размер структуры
            imageHeader.biSize = (uint)Marshal.SizeOf(typeof(BITMAPINFOHEADER)); 

            // указать фиксированные данные
            imageHeader.biPlanes        =   1; imageHeader.biBitCount     =   8; 
            imageHeader.biCompression   =   0; imageHeader.biSizeImage    =   0; 
            imageHeader.biClrUsed       = 256; imageHeader.biClrImportant = 256; 

            // указать число пикселов на метр по горизонтали и вертикали
            imageHeader.biXPelsPerMeter = (int)((header.HorizontalDPI * 1000) / 25.4); 
            imageHeader.biYPelsPerMeter = (int)((header.VerticalDPI   * 1000) / 25.4); 

            // указать размеры изображения
            imageHeader.biWidth  =  (int)header.Width;  fileHeader.bfReserved1 = 0;
            imageHeader.biHeight = -(int)header.Height; fileHeader.bfReserved2 = 0;

            // выделить память для таблицы цветов
            RGBQUAD[] colors = new RGBQUAD[imageHeader.biClrUsed]; 

            // определить размер таблицы цветов
            uint sizeColors = (uint)(Marshal.SizeOf(typeof(RGBQUAD)) * colors.Length); 

            // определить размер заголовка файла
            uint sizeFileHeader = (uint)Marshal.SizeOf(typeof(BITMAPFILEHEADER)); 

            // вычислить смещение массива точек
            fileHeader.bfOffBits = (sizeFileHeader + imageHeader.biSize + sizeColors); 
            
            // вычислить общий размер файла
            fileHeader.bfSize = fileHeader.bfOffBits + (uint)points.Length; 

            // для всех цветов в таблице
            for (int i = 0; i < colors.Length; i++)
            {
                // указать используемые составляющие
                colors[i].rgbRed  = (byte)i; colors[i].rgbGreen = (byte)i; 
                colors[i].rgbBlue = (byte)i; colors[i].rgbAlpha = (byte)0; 
            }
            // выделить буфер требуемого размера
            IntPtr buffer = Marshal.AllocHGlobal((int)fileHeader.bfSize); 

            // скопировать заголовок .BMP-файла
            Marshal.StructureToPtr(fileHeader, buffer, false); 

            // перейти на следующие данные
            IntPtr ptr = new IntPtr(buffer.ToInt64() + sizeFileHeader); 

            // скопировать заголовок описания изображения
            Marshal.StructureToPtr(imageHeader, ptr, false); 

            // перейти на следующие данные
            ptr = new IntPtr(ptr.ToInt64() + imageHeader.biSize); 
            
            // скопировать таблицу цветов
            Marshal.StructureToPtr(colors, ptr, false); 

            // перейти на следующие данные
            ptr = new IntPtr(ptr.ToInt64() + imageHeader.biSize); 
            
            // скопировать содержимое точек
            Marshal.Copy(points, 0, ptr, points.Length); 

            // выделить буфер требуемого размера
            byte[] bitmap = new byte[fileHeader.bfSize]; 

            // скопировать содержимое .BMP-файла
            Marshal.Copy(buffer, bitmap, 0, bitmap.Length); 

            // освободить выделенную память
            Marshal.FreeHGlobal(buffer); return bitmap; 
        } 
        ///////////////////////////////////////////////////////////////////////
        // Прочитать .BMP-изображение
        ///////////////////////////////////////////////////////////////////////
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public static byte[] Read(IntPtr ptrBitmap)
        {
            // проверить наличие указателя
            if (ptrBitmap == null) return null; 
                    
            // указать тип заголовка
            Type typeHeader = typeof(NativeMethods.IMAGE_HEADER); 
                        
            // указать размер заголовка
            int sizeHeader = Marshal.SizeOf(typeHeader); 

            // прочитать заголовок
            NativeMethods.IMAGE_HEADER imageHeader = 
                (NativeMethods.IMAGE_HEADER)
                    Marshal.PtrToStructure(ptrBitmap, typeHeader); 

            // пропустить заголовок
            ptrBitmap = new IntPtr(ptrBitmap.ToInt64() + sizeHeader); 

            // выделить память для описания точек
            byte[] points = new byte[imageHeader.Width * imageHeader.Height]; 

            // прочитать описание точек
            Marshal.Copy(ptrBitmap, points, 0, points.Length); 

            // создать Bitmap-изображение
            return Create(imageHeader, points);
        }
    }
}

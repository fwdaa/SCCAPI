using System;
using System.Runtime.InteropServices;

namespace Aladdin.CAPI.Bio.BSAPI
{
	///////////////////////////////////////////////////////////////////////
	// Описание формата изображения
	///////////////////////////////////////////////////////////////////////
    [StructLayout(LayoutKind.Sequential)]
    public struct ImageFormat {			 // описание формата изображения
        public UInt16 ScanResolutionH; 	 // горизонтальное разрешение сканирования (в точках на дюйм)
        public UInt16 ScanResolutionV; 	 // вертикальное разрешение сканирования   (в точках на дюйм)
        public UInt16 ImageResolutionH;  // горизонтальное разрешение изображения  (в точках на дюйм)
        public UInt16 ImageResolutionV;  // вертикальное разрешение изображения    (в точках на дюйм)
        public Byte   ScanBitsPerPixel;  // число битов в пикселе при сканировании
        public Byte   ImageBitsPerPixel; // число битов в пикселе изображения
    }
}

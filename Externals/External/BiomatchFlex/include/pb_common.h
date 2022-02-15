/*! \file pb_common.h
\brief 
BioMatch Common Header File
\details
Contains the core definitions and functionality for Precise Biometrics 
BioMatch 
technology and reader intergration. 
\anchor acronyms
\par Acronyms
- ANSI - American National Standards Institute
- FAR - False Acceptance Rate
- FRR - False Rejection Rate
- ISO - International Standards Organization
- MoC - Match-On-Card
- NIST - National Institute of Standards and Technology
- SDK - Software Development Kit

\anchor ASCII
\anchor UNICODE
\par ASCII and UNICODE
The main way of selecting the reader to use in an operation is by it's 
friendly name. The toolkit have support for both ASCII and UNICODE strings. 
All functions that uses strings are implemented as both an ASCII version and a
UNICODE version. ASCII versions of a functions have a 'A' appended to it's 
name while the UNICODE version have a 'W' appended. The 'A' and 'W' function 
should not be called directly. The user should call the defined funcion 
wihtout 'A' and 'W'. In this way the correct implementation of the function is
always selected according to the build environment. The user should for 
example call pb_cancel instead of pb_cancelA()/pb_cancelW() directly. 
\code
//example how pb_cancel is defined.
#ifdef UNICODE
#define pb_cancel pb_cancelW
#else
#define pb_cancel pb_cancelA
#endif
\endcode
The following functions has both an ASCII and a UNICODE implementation.\n
- pb_cancel {pb_cancelA(), pb_cancelW()}\n
- pb_capture_image {pb_capture_imageA(), pb_capture_imageW()}\n
- pb_capture_raw_image {pb_capture_raw_imageA(), pb_capture_raw_imageW()}\n
- pb_list_readers {pb_list_readersA(), pb_list_readersW()}\n
- pb_wait_for_no_finger {pb_wait_for_no_fingerA(), pb_wait_for_no_fingerW()}\n


\par Smart Card Functions
A couple of reader specific operations are implemented in two variants. 
The functionality in these functions are equivalent but the way the reader is 
identified varies. Normally a reader is identified with it's friendly name. 
This way of identifying the reader might not work if the user has opened a 
private session to a smart card in the reader. The way to identify the reader 
in such cases is with the previously opened SCARDHANDLE. Smart card functions 
in the toolkit are given 'pb_sc_' as prefix instead of the ordinary 'pb_' 
prefix. \n
The following functions are defined in the toolkit. \n
- #pb_sc_cancel()\n
- #pb_sc_capture_image()\n
- #pb_sc_capture_raw_image()\n
- #pb_sc_wait_for_no_finger()\n

*/

#ifndef HEADER_PB_COMMON_H
#define HEADER_PB_COMMON_H

#include <stdlib.h>
#include <limits.h>

#ifdef _WIN32
#if !defined(PBCOMMON_NO_PCSC)
#include <winscard.h>
#endif

#if defined(_WIN32)
#ifdef PBTRIAL
#include ".\Trial\trial.h"
#endif
#endif

/*!
\name Calling convention
@{
\def PBCALL
Exported functions follow the __cdecl calling convention. 
*/
#undef PBCALL
#define PBCALL __cdecl
#else
#undef PBCALL
#define PBCALL
#endif
/*@}*/

/*!
\name BioMatch boolean
@{
The standard convention for boolean values in C is to use an 'int'. 
Furthermore, the C standard says that 0 is treated as 'false' and all other 
values as 'true', but the built-in logical operators will always return 1 as 
'true'. The same convention is used in BioMatch; the Boolean parameters are 
declared as 'int', non-zero in-parameters are treated as 'true', but functions
returning boolean values will only return 0 or 1. 
\def PB_TRUE 
True
\def PB_FALSE 
False
*/
#define PB_TRUE 1
#define PB_FALSE 0
/*@}*/

/*!
\anchor error
\name Error codes. 
@{
Error codes are reserved for real errors (such as there is not enough memory 
for the function to succeed), so a function may return "success" even if it in
some sense does fail. For example, a failed match return success, but an 
out-parameter will communicate that the matching failed.\n\n
All such error codes (that are not mentioned in the function definitions) 
may however be regarded as "catastrophic failures", in the sense that they 
should not be able to happen, and the only sensible thing to do for a caller 
that receives such an error is to exit (preferably after informing the user 
that something unexpected has happened.) The out-parameters should be 
considered to have "undefined" values when a function returns an error code 
different from #PB_EOK.
\def PB_EOK          	
The function returned without errors. 
\def PB_EBUFFER      	
At least one buffer has an incorrect size. 
\def PB_ECANCEL      	
The function returned because the caller canceled it. 
\def PB_EFATAL       	
An undefined fatal error has occurred. This error code is used for errors that
"cannot happen" and isn't covered by any other error code. 
\def PB_EBIR        	
The BIR is corrupt or not recognized as a BIR of the correct type. 
\def PB_EDATA       	
The data passed to the function is not of the correct format. 
\def PB_EREADER      	
The reader name does not represent any connected reader. 
\def PB_EMEMORY      	
Cannot allocate enough memory. 
\def PB_EINIT       	
A function is called before the interface being initialized. 
\def PB_ESUPPORT    	
The requested operation is not supported by the implementation. 
\def PB_EPARAMETER  	
At least one of the parameters is invalid. 
\def PB_EBUSY
The reader is already in use.
\def PB_ETIMEOUT    	
The operation timed-out before it could finish the operation. 
\def PB_EQUALITY    	
The fingerprint image is of too poor quality.
\def PB_ETRIAL
The trial is not valid (Only in trial version).
*/
#define PB_EOK                                      0 
#define PB_EBUFFER                                  1 
#define PB_ECANCEL                                  2 
#define PB_EFATAL                                   3 
#define PB_EBIR                                     4 
#define PB_EDATA                                    5 
#define PB_EREADER                                  6 
#define PB_EMEMORY                                  9 
#define PB_EINIT                                    12 
#define PB_ESUPPORT                                 13 
#define PB_EPARAMETER                               14 
#define PB_EBUSY                                    15
#define PB_ETIMEOUT                                 16 
#define PB_EQUALITY                                 23 
#if defined(_WIN32)
#ifdef PBTRIAL
#define PB_ETRIAL                                   30 
#endif
#endif
/*@}*/

/*!
\anchor quality
\par Finger Quality 
The quality value details the quality of an image. 
It is coded in the same way as in BioAPI, that is, in the range 0-100, with 
the following interpretation.

0-25:	UNACCEPTABLE: The biometric data cannot be used for the purpose 
specified by the caller.\n
26-50:	MARGINAL: The biometric data will provide poor performance for the 
purpose specified by the caller and in most application environments will 
compromise the intent of the application. The biometric data should be 
replaced with a new sample.\n
51-75:	ADEQUATE: The biometric data will provide good performance in most 
application environments based on the purpose specified by the caller.\n
76-100:	EXCELLENT: The biometric data will provide good performance for the 
purpose specified by the caller.\n

The values -1 and -2 have a special meaning:\n
-1:	NOT SET: Output parameters may be set to this if the function fails.\n
-2:	NOT SUPPORTED: Quality measurement is not supported by the 
implementation.\n

The returned quality parameter only reports if the image is acceptable or not,
i.e. it does not have the granularity to say if an acceptable image is of a 
better quality than another acceptable image. It is in general better to 
ignore the quality value, and just look at the finger condition value.

\par Finger Conditions
The following different conditions for a fingerprint are defined in the 
toolkit. 
\name Fingerprint Information
\anchor condition
@{
\brief Fingerprint detailed information in BioMatch toolkit.
\details
Knowing the quality of the finger in an image is vital for a successful 
implementation. 
The following indicators can be given from pb_finger_status.

\def PB_STATUS_OK   
The quality of the fingerprint is good.
\def PB_STATUS_UNKNOWN
The status of the finger is unknown alt. there is no finger in the image.
\def PB_STATUS_TOO_WET
The finger is to wet and/or the finger is pressed to hard on the sensor. 
\def PB_STATUS_TOO_DRY
The finger is too dry and/or the finger is placed to gently on the sensor.
\def PB_STATUS_TOO_SMALL
The captured fingerprint area is too small to do any operations.
\def PB_STATUS_BAD_FINGER
The captured fingerprint image is of too bad quality to do any biometric 
operations. 
The cause of this could be a very worn or dirty finger. 
*/
#define PB_STATUS_OK            0
#define PB_STATUS_TOO_WET       1
#define PB_STATUS_TOO_DRY       2
#define PB_STATUS_TOO_SMALL     3
#define PB_STATUS_BAD_FINGER    4
#define PB_STATUS_UNKNOWN       -1
/*
@}
*/

/*!
\name Timeout
@{
\brief Pre-defined timeout values.
\def PB_TIMEOUT_FOREVER
Pre-defined value to never let a function timeout (UINT_MAX == 0xffffffff) 
*/
#define PB_TIMEOUT_FOREVER                          UINT_MAX
/*@}*/

/*!
\anchor FAR
\name Security settings
@{
Depending on what the system is going to be used for, different FAR levels can
be chosen. The FAR level is specified during enrollment and the specified 
level is stored on the smart card as a part of the secure reference data. 
Though any numerical level may be chosen, five predefined FAR parameters are 
specified and the FAR for each is shown in the table below. 
For example, PB_FAR_10000 means that 10,000 imposter attempts, i.e. 10,000 
fingers, are on average needed to produce one (1) false accept.
\n\n
The FAR is inversely related to the FRR such that a decreasing FAR will result
in an increasing FRR, e.g. PB_FAR_100 in the table will result in a much lower
FRR than PB_FAR_1000000. Therefore it is recommended not to choose a lower FAR
level than required by the system. A FAR value of 1:10,000 (PB_FAR_10000) is 
recommended unless the customer explicitly wants a lower value. The FRR is not
only dependent on the FAR, but also on a lot of abstract parameters, such as:
\n\n
- The users experience of the fingerprint reader.\n
- The quality of the enrolled fingerprint template.\n
- The skin condition of the users fingerprint.\n
- When the last cleaning of the fingerprint sensor was made.\n
\n

This implies that different individuals will achieve different FRR although 
the same FAR level is used. A custom FAR is generated by the division 
0x7fffffff/n where n is the required FAR level. So 0x7fffffff/10000 is 
equivalent to PB_FAR_10000. The FRR will always be optimized to be as low as 
possible given a specific FAR level.

\def PB_FAR_100
False Acceptance Rate 1:100
\def PB_FAR_1000
False Acceptance Rate 1:1000
\def PB_FAR_10000
False Acceptance Rate 1:10000
\def PB_FAR_100000
False Acceptance Rate 1:100000
\def PB_FAR_1000000
False Acceptance Rate 1:1000000
*/
#define PB_FAR_100                                  (0x7fffffff/100)    
#define PB_FAR_1000                                 (0x7fffffff/1000)
#define PB_FAR_10000                                (0x7fffffff/10000)      
#define PB_FAR_100000                               (0x7fffffff/100000)     
#define PB_FAR_1000000                              (0x7fffffff/1000000)    
/*@}*/
/*!
\anchor encoded
\name Image encoding
@{
\def PB_ENCODING_8_BIT_GRAYSCALE
8 bit grayscale image. 0 = black, 255 = white. 
*/
#define PB_ENCODING_8_BIT_GRAYSCALE                 0
/*@}*/


/*@}*/
/*!
\anchor finger
\name Finger Position
Individual finger positions are encoded in the same way as ANSI378-2004 
and ISO19794-2 First Edition, as described in ANSI/NIST-ITL 1-2000.
@{
\def PB_FINGER_UNKNOWN
Unknown finger. 
\def PB_FINGER_RIGHT_THUMB
Right thumb.
\def PB_FINGER_RIGHT_INDEX
Right index finger.
\def PB_FINGER_RIGHT_MIDDLE
Right ring finger.
\def PB_FINGER_RIGHT_RING
Right little finger.
\def PB_FINGER_RIGHT_LITTLE
Left thumb.
\def PB_FINGER_LEFT_THUMB
Left index finger.
\def PB_FINGER_LEFT_INDEX
Left middle finger.
\def PB_FINGER_LEFT_MIDDLE
Left ring finger.
\def PB_FINGER_LEFT_RING
Left ring finger.
\def PB_FINGER_LEFT_LITTLE
Left little finger.
*/
#define PB_FINGER_UNKNOWN       0
#define PB_FINGER_RIGHT_THUMB   1
#define PB_FINGER_RIGHT_INDEX   2
#define PB_FINGER_RIGHT_MIDDLE  3
#define PB_FINGER_RIGHT_RING    4
#define PB_FINGER_RIGHT_LITTLE  5
#define PB_FINGER_LEFT_THUMB    6
#define PB_FINGER_LEFT_INDEX    7
#define PB_FINGER_LEFT_MIDDLE   8
#define PB_FINGER_LEFT_RING     9
#define PB_FINGER_LEFT_LITTLE   10
/*@}*/

/*!
\anchor sensor
\name Sensors & Fingerprint readers
@{
Knowing what type of sensor that was used when capturing a fingerprint image 
can improve the biometric performance. The following readers / sensors are 
currently recognized by Precise BioMatch. Some sensors / readers share the 
same values as they are treated the same way internally. When constructing a 
fingerprint image with data from an external source the preferred value is 
#PB_SENSOR_UNKNOWN unless that exact sensor is listed below. 
\def PB_SENSOR_UNKNOWN
Unknown sensor / generic image
\def PB_SENSOR_AUTHENTEC_AES2501
Authentec AES2501 swipe sensor.
\def PB_SENSOR_AUTHENTEC_AES2550
Authentec AES2550 swipe sensor.
\def PB_SENSOR_AUTHENTEC_AES2810
Authentec AES2810 swipe sensor.
\def PB_SENSOR_UPEK_TCS1     
UPEK TCS1 area sensor (used in Precise 250 MC)
\def PB_SENSOR_UPEK_TCS2                         
UPEK TCS2 area sensor (used in Precise 200 MC)
\def PB_SENSOR_UPEK_TCS3                      
UPEK TCS3 swipe sensor. 
\def PB_SENSOR_UPEK_TCS4
UPEK TCS4 swipe sensor.
\def PB_SENSOR_UPEK_TCS5
UPEK TCS5 swipe sensor.
\def PB_SENSOR_CROSSMATCH_300LC                  
Crossmatch 300 LC
\def PB_SENSOR_PRECISE_100XS                     
Precise Biometrics 100 XS
\def PB_SENSOR_PRECISE_200MC                     
Precise Biometrics 200 MC
\def PB_SENSOR_PRECISE_250MC                     
Precise Biometrics 250 MC
*/
#define PB_SENSOR_UNKNOWN                           0
#define PB_SENSOR_AUTHENTEC_AES2501                 17
#define PB_SENSOR_AUTHENTEC_AES2550                 24
#define PB_SENSOR_AUTHENTEC_AES2810                 25
#define PB_SENSOR_UPEK_TCS1                         20
#define PB_SENSOR_UPEK_TCS2                         14
#define PB_SENSOR_UPEK_TCS3                         21
#define PB_SENSOR_UPEK_TCS4                         22
#define PB_SENSOR_UPEK_TCS5                         26
#define PB_SENSOR_CROSSMATCH_300LC                  0
#define PB_SENSOR_PRECISE_100XS                     17
#define PB_SENSOR_PRECISE_200MC                     14
#define PB_SENSOR_PRECISE_250MC                     20
/*@}*/

/*! 
\name Image type
@{
\struct pb_image_t
\brief 
Precise Biometrics image data type.
\details
This is the commonly used way of working with fingerprint images in the
BioMatch Toolkit. The structure contains information regarding the image
itself, details about the fingerprint, what sensor was used for acquiring the 
image as well as the raw image data. 
\param size_x 
Image width in pixels.
\param size_y 
Image height in pixels.
\param resolution_x
Image width resolution in dpi.
\param resolution_y
Image height resolution in dpi.
\param sensor
The \ref sensor used for image capture. 
\param encoding
The way the image data is \ref encoded. 
\param finger
What \ref finger position the finger has. 
\param raw_data 
Array of data containing the image. 
The size of the array is size_x * size_y bytes.
\note 
When constructing images for display on Windows platform size_x should be 
equal to size_x rounded up to the nearest value so that size_x mod 4 = 0. 
*/
typedef struct 
{
    unsigned __int32 size_x;
    unsigned __int32 size_y;
    unsigned __int32 resolution_x;
    unsigned __int32 resolution_y;
    __int32 sensor;
    __int32 encoding;
    __int32 finger;
    unsigned char* raw_data;
} pb_image_t;
/*@}*/

/*! \typedef pb_cb_t
\brief 
BioMatch callback definition.
\details
This function is to be implemented by developers wishing to utilize the 
callback functionality supported by the toolkit. The callback is called at 
suitable occasions during the current operation. For area type readers, it 
will typically be called each time a new image is read from the sensor, but an
application must not assume that the reader captures images in a stream. 
For example, some sensors do not return an image unless there is a finger 
present on the sensor, and stripe sensors only capture exactly one image of 
the finger. The application may however assume that the callback will return 
immediately with an image when a verification/enrollment/capture function is 
called, so that it does not need to write out finger status information etc. 
before it calls the function (but it may then take an arbitrarily long time 
before the callback is called the next time). For readers that don't return a 
stream of images, this first image will probably be an empty image. The 
callback will be executed in the same context as the caller (this permit the 
caller to use thread local storage etc. It also makes it much safer for 
platforms where a non-threaded application may call a threaded library.)
The 'pb_cb_' functions are the only 'pb_'-functions that are guaranteed to 
work when called from the callback.
\param[out] token
Token provided by the toolkit. 
\param[in,out] [context]
This parameter is the same as the caller passed to the original operation. 
It is completely up to the implementation to use it as it sees fit.
\code
// example of a callback that checks if a finger is placed on the sensor
void pb_callback(int token, void* context)
{
    int ret, present;
    ret = pb_cb_finger_status(token, NULL, NULL, NULL, NULL, &present)
    if (ret != PB_EOK)
        return;
    if(!present)
        printf("place finger on reader...");
}
\endcode
*/
typedef void (PBCALL *pb_cb_t)(int, void*);

#ifdef __cplusplus
extern "C" {
#endif

    /*!
    \fn int PBCALL pb_cb_cancel(int token);
    \brief Cancels an on-going operation from within an image callback.
    \details
    The cancelled operation will return with the error code #PB_ECANCEL, and 
    the cancel state is cleared when #PB_ECANCEL is returned. 
    It is only the functions that have a timeout parameter that are 
    cancelable; other functions are unaffected. The function returns #PB_EOK 
    even if there are no active operations. The function will not wait for the
    operation to cancel (this is so that it may be called from callbacks 
    without causing a deadlock.) An application may however not assume that 
    this call returns before the cancelled function returns.
    @param[in] token 
    Token received from callback. 
    \retval 
    #PB_EOK if successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    */
    int PBCALL pb_cb_cancel(int token);

    /*!
    \fn int PBCALL pb_cb_finger_status(int token, pb_image_t** image, int* 
    quality, int* condition, int* present);
    \brief Provides "live" information about finger on the sensor.
    \details
    This function is called from within a callback function to retrieve 
    information about the finger currently on the sensor or to retrieve the 
    actual image itself. All parameters in this function are optional. 
    As some parameters require comlpex processing it is recommended only to 
    retrieve the information that is required in the set context. Parameters 
    that aren't required shall be set to NULL. 
    The image data needs to be freed with pb_free_image() when it is no 
    longer needed.
    \param[in]  
    token     
    Token provided by the toolkit. 
    \param[out] [image]       
    pointer to an pb_image_t. 
    \param[out] [quality]     
    A measure of the \ref quality of the image.
    \param[out] [condition]     
    The \ref condition of the finger. 
    \param[out] [present]     
    Returns #PB_TRUE if there is a finger present in the image, and #PB_FALSE 
    otherwise.
    \retval 
    #PB_EOK if successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    */
    int PBCALL pb_cb_finger_status(
        int token, 
        pb_image_t** image, 
        int* quality, 
        int* condition, 
        int* present);

    /*!
    \fn int PBCALL pb_cb_get_image_for_viewing(int token, unsigned int size_X,
    unsigned int size_Y, unsigned int stride_X, unsigned char** image_data, 
    unsigned int* image_size);
    \brief
    Returns a grayscale image that is suitable for use as user feedback on 
    finger placement.
    \details
    Creates an image of the fingerprint that is suitable for display on 
    screen. The image is returned as an array of data with the specified size 
    and stride. This image is processed for vieweing purposes and should never
    be used for enrolment or verification.
    \param[in] token 
    Token received from callback. 
    \param[in] size_X
    Target image width in pixels.
    \param[in] size_Y
    Target image height in pixels.
    \param[in] stride_X
    Allocated bytes per image row. This value is always larger or equel to 
    size_X.
    \param[out] image_data
    Array of data containing the newly constructed image. This data needs to 
    be freed with pb_free() when it is no longer needed.
    \param[out] image_size
    The length of the newly allocated array of image data. 
    \retval 
    #PB_EOK if successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    \note 
    When constructing images for display on Windows platform stride_X should 
    be equal to size_X rounded up 
    to the nearest value so that stride_X mod 4 = 0.
    */
    int PBCALL pb_cb_get_image_for_viewing(
        int token, 
        unsigned int size_X, 
        unsigned int size_Y, 
        unsigned int stride_X, 
        unsigned char** image_data, 
        unsigned int* image_size);

    /*! 
    \fn int PBCALL pb_free(void* buffer);
    \brief 
    Frees allocated memory.
    \details
    Frees memory that has been allocated by the framework, 
    such as the data returned from pb_list_readers. 
    \param[in] buffer 
    Pointer to the memory to be freed.
    \retval 
    #PB_EOK if successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    */
    int PBCALL pb_free(void* buffer);

    /*!
    \fn int PBCALL pb_free_image(pb_image_t* image);
    \brief 
    Frees allocated memory.
    \details 
    Frees memory of an image that has been allocated by the framework, 
    such as the data returned from pb_capture_image. 
    \param[in] image 
    Pointer to the pb_image_t structure to be freed.
    \retval 
    #PB_EOK if successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    */
    int PBCALL pb_free_image(pb_image_t* image);

    /*!
    \fn int PBCALL pb_initialize(void);
    \brief 
    Initializes the BioMatch framework.
    \details
    This is function need to be called once prior to any other calls. 
    Calling this function may take a couple of seconds depending on the 
    number of supported readers that need to be enumerated and initialized. 
    It is recommended to call this function only once on application startup. 
    The framework is closed by calling pb_release().
    \retval 
    #PB_EOK if successful.
    \retval
    #PB_ETRIAL if trial validation was not successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    */
    int PBCALL pb_initialize(void);

    /*!
    \fn int PBCALL pb_release(void);
    \brief 
    Closes the BioMatch framework.
    \details 
    Closes the BioMatch framework and releases resources allocated by 
    a previous call to pb_initialize(). 
    \retval 
    #PB_EOK if successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    */
    int PBCALL pb_release(void);

#ifdef _WIN32

    /*!
    \fn int PBCALL pb_list_readersA(LPSTR* reader_list, int* nof_readers);
    \brief 
    Lists available readers.
    \details
    Lists the currently conneced readers and returns the list as a 
    multi-string. The order of the readers in the array is arbitrary but 
    consistent, i.e. the relative position of the readers in the list is the 
    same between calls (this means that an application that displays the 
    readers may write them out in order, without risking that the readers 
    "jump around" in the list.) The order may change if the application is 
    shut down and restarted between calls. A reader that currently is used by 
    another process can be listed with a different name. If there are no 
    readers available, the reader list will be NULL. (i.e. no empty structure 
    will be allocated). The reader list needs to be freed by a call to 
    pb_free() when it is no longer needed.
    \param[out] reader_list 
    Multi-string of readers. A double NULL terminates the list of values. 
    \param[out] nof_readers
    The number of found readers. 
    \retval 
    #PB_EOK if successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    \invariant 
    This function exists as a ASCII implementation pb_list_readersA() and as a
    UNICODE implementation pb_list_readersW()
    \note
    This function should not be called directly. Always call the macro version
    of the function; pb_list_readers.   
    */
    int PBCALL pb_list_readersA(LPSTR* reader_list, int* nof_readers);

    /*!
    \copydoc pb_list_readersA
    */
    int PBCALL pb_list_readersW(LPWSTR* reader_list, int* nof_readers);

#ifdef UNICODE
#define pb_list_readers pb_list_readersW
#else
#define pb_list_readers pb_list_readersA
#endif

    /*!
    \fn int PBCALL pb_capture_imageA(LPSTR reader, unsigned int timeout, 
    pb_image_t** image, pb_cb_t callback, void* context);
    \brief
    Captures an image from the sensor.
    \details
    This function waits for the fingerprint image to stabilize and achieve 
    sufficient quality before returning. The image data needs to be freed by a
    call to pb_free_image() when it is no longer needed.
    \param[in] reader
    The reader to use. 
    \param[in] timeout
    The timeout parameter specifies the timeout for the operation (in ms.). 
    If this timeout is reached, the error #PB_ETIMEOUT is returned. 
    If timeout is set to #PB_TIMEOUT_FOREVER then the function will never time
    out.
    \param[out] image
    The final image from the reader.
    \param[in] [callback]
    The callback is called for each image that is read from the sensor, and 
    used to provide feedback to the user during the operation.
    See #pb_cb_t for a detailed description of the image callback mechanism. 
    The user-supplied pointer context is used as a parameter to the callback. 
    This can be used by an application as it sees fit. 
    Both callback and context are optional. 
    However, callback must be specified if context is present.
    \param[in,out] [context]
    Pointer to user defined data.
    \retval 
    #PB_EOK if successful.
    \retval 
    #PB_ETIMEOUT is returned if an image with sufficient quality has not been
    captured within the specified time. 
    \retval 
    #PB_ECANCEL is returned if the operation has been cancelled by a call to 
    pb_cancel or pb_cb_cancel().
    \returns 
    Other possible return values are defined in \ref error codes.
    \invariant 
    This function exists as a ASCII implementation pb_capture_imageA(), as a 
    UNICODE implementation pb_capture_imageW() and as pb_sc_capture_image() 
    that will use a SCARDHANDLE instead of a reader name when specifying the 
    reader to use. 
    \note
    This function should not be called directly. Always call the macro version
    of the function; pb_capture_image.   

    */
    int PBCALL pb_capture_imageA(
        const LPSTR reader, 
        unsigned int timeout, 
        pb_image_t** image, 
        pb_cb_t callback, 
        void* context);

    /*!
    \copydoc pb_capture_imageA
    */
    int PBCALL pb_capture_imageW(
        const LPWSTR reader, 
        unsigned int timeout, 
        pb_image_t** image, 
        pb_cb_t callback, 
        void* context);

#ifdef UNICODE
#define pb_capture_image pb_capture_imageW
#else
#define pb_capture_image pb_capture_imageA
#endif

#endif

    /*!
    \fn int PBCALL pb_wait_for_no_fingerA(LPSTR reader, unsigned int timeout, 
    pb_cb_t callback, void* context);      
    \brief
    Captures images from the sensor until an empty image is received. 
    \details
    This function can be called to ensure that the finger is lifted between 
    operations. 
    \param[in] reader
    The reader to use. 
    \param[in] timeout
    The timeout parameter specifies the timeout for the operation (in ms.). 
    If this timeout is reached, the error #PB_ETIMEOUT is returned. 
    If timeout is set to #PB_TIMEOUT_FOREVER then the function will never time
    out.
    \param[in] [callback]
    The callback is called for each image that is read from the sensor, and 
    used to provide feedback to the user during the operation.
    See #pb_cb_t for a detailed description of the image callback mechanism. 
    The user-supplied pointer context is used as a parameter to the callback. 
    This can be used by an application as it sees fit. 
    Both callback and context are optional. 
    However, callback must be specified if context is present.
    \param[in,out] [context]
    Pointer to user defined data.
    \retval 
    #PB_EOK if successful.
    \retval 
    #PB_ETIMEOUT is returned if an image with sufficient quality has not been 
    captured within the specified time. 
    \retval 
    #PB_ECANCEL is returned if the operation has been cancelled by a call to 
    pb_cancel or pb_cb_cancel().
    \returns 
    Other possible return values are defined in \ref error codes.
    \invariant 
    This function exists as a ASCII implementation pb_wait_for_no_fingerA() 
    and as a UNICODE implementation pb_wait_for_no_fingerW()
    \note
    This function should not be called directly. Always call the macro version
    of the function; pb_wait_for_no_finger.   
    */
    int PBCALL pb_wait_for_no_fingerA(
        const LPSTR reader, 
        unsigned int timeout, 
        pb_cb_t callback, 
        void* context);      

    /*!
    \copydoc pb_wait_for_no_fingerA()
    */
    int PBCALL pb_wait_for_no_fingerW(
        const LPWSTR reader, 
        unsigned int timeout, 
        pb_cb_t callback, 
        void* context);       

#ifdef UNICODE
#define pb_wait_for_no_finger pb_wait_for_no_fingerW
#else
#define pb_wait_for_no_finger pb_wait_for_no_fingerA
#endif
    /*!
    \fn int PBCALL pb_capture_raw_imageA(LPSTR reader, pb_image_t** image);
    \brief
    Capture a raw image.
    \details
    Captures a raw image from the sensor. Unlike pb_capture_image this 
    function return immediately once an image has been captured. This function
    is mainly used for reader diagnostics. The function should not be used to 
    capture images used for template creation. 
    \param[in] reader
    The reader to use.
    \param[out] image
    The captured image.
    \retval 
    #PB_EOK if successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    \invariant 
    This function exists as a ASCII implementation pb_capture_raw_imageA(), as
    a UNICODE implementation pb_capture_raw_imageW() and as 
    pb_sc_capture_raw_image() that will use a SCARDHANDLE instead of a reader 
    name when specifying the reader to use. 
    \note
    This function should not be called directly. Always call the macro version
    of the function; pb_capture_raw_image.   

    */
    int PBCALL pb_capture_raw_imageA(const LPSTR reader, pb_image_t** image);

    /*!
    \copydoc pb_capture_raw_imageA
    */
    int PBCALL pb_capture_raw_imageW(const LPWSTR reader, pb_image_t** image);

#ifdef UNICODE
#define pb_capture_raw_image pb_capture_raw_imageW
#else
#define pb_capture_raw_image pb_capture_raw_imageA
#endif

#if !defined(PBBASE_NO_PCSC)
    /*!
    \fn int PBCALL pb_sc_capture_image(SCARDHANDLE reader, unsigned int 
    timeout, pb_image_t** image, pb_cb_t callback, void* context);
    \brief
    Captures an image from the sensor.
    \details
    This function waits for the fingerprint image to stabilize and achieve 
    sufficient quality before returning.
    The image data needs to be freed by a call to pb_free_image() when it is 
    no longer needed.
    \param[in] reader
    Handle to smart card received from previous call to SCardConnect(). 
    \param[in] timeout
    The timeout parameter specifies the timeout for the operation (in ms.). 
    If this timeout is reached, the error #PB_ETIMEOUT is returned. 
    If timeout is set to #PB_TIMEOUT_FOREVER then the function will never time
    out.
    \param[out] image
    The final image from the reader.
    \param[in] [callback]
    The callback is called for each image that is read from the sensor, and 
    used to provide feedback to the user during the operation.
    See #pb_cb_t for a detailed description of the image callback mechanism. 
    The user-supplied pointer context is used as a parameter to the callback. 
    This can be used by an application as it sees fit. 
    Both callback and context are optional. 
    However, callback must be specified if context is present.
    \param[in,out] [context]
    Pointer to user defined data.
    \retval 
    #PB_EOK if successful.
    \retval 
    #PB_ETIMEOUT is returned if an image with sufficient quality has not been 
    captured within the specified time. 
    \retval 
    #PB_ECANCEL is returned if the operation has been cancelled by a call to 
    pb_cancel or pb_cb_cancel().
    \returns 
    Other possible return values are defined in \ref error codes.
    \invariant 
    This function exists as a ASCII implementation pb_capture_imageA(), as a 
    UNICODE implementation pb_capture_imageW() and as pb_sc_capture_image() 
    that will use a SCARDHANDLE instead of a reader name when specifying the 
    reader to use. 
    */
    int PBCALL pb_sc_capture_image(
        SCARDHANDLE reader, 
        unsigned int timeout, 
        pb_image_t** image, 
        pb_cb_t callback, 
        void* context);

    /*!
    \copydoc pb_cancelA()
    */
    int PBCALL pb_sc_cancel(SCARDHANDLE reader);

    /*!
    \copydoc pb_capture_raw_imageA()
    */
    int PBCALL pb_sc_capture_raw_image(
        SCARDHANDLE reader, 
        pb_image_t** image);

    /*!
    \copydoc pb_wait_for_no_fingerA()
    */
    int PBCALL pb_sc_wait_for_no_finger(
        SCARDHANDLE reader, 
        unsigned int timeout, 
        pb_cb_t callback, 
        void* context);
#endif

    /*!
    \fn int PBCALL pb_finger_status(const pb_image_t* image, int* quality, 
    int* condition, int* present);
    \brief
    Retrieves information about the finger in an image.
    \details
    Used to retrieve information about a fingerprint image. Most parameters 
    are optional. As some parameters require comlpex processing it is 
    recommended only to retrieve the information that is required in 
    the set context. Parameters that aren't required shall be set to NULL.
    \param[in] image
    Image that the operation works on.
    \param[out] [quality]     
    A measure of the \ref quality of the image.
    \param[out] [condition]     
    The \ref condition of the finger. 
    \param[out] [present]
    Returns PB_TRUE if there is a finger present in the image, and PB_FALSE 
    otherwise.
    \retval 
    #PB_EOK if successful.
    \retval
    #PB_ETIMEOUT is returned if an image with sufficient quality has not been
    captured within the specified time. 
    \retval 
    #PB_ECANCEL is returned if the operation has been cancelled by a call to 
    pb_cancel or pb_cb_cancel().
    \returns 
    Other possible return values are defined in \ref error codes.
    */
    int PBCALL pb_finger_status(
        const pb_image_t* image, 
        int* quality, 
        int* condition, 
        int* present);

    /*!
    \fn int PBCALL pb_get_image_for_viewing(const pb_image_t* image, 
    unsigned int size_X, unsigned int size_Y, unsigned int stride_X, 
    unsigned char** image_data, unsigned int* image_size);
    \brief
    Returns a grayscale image that is suitable for use as user feedback on 
    finger placement.
    \details
    Creates an image of the fingerprint that is suitable for display on 
    screen. The image is returned as an array of data with the specified size 
    and stride. This image is processed 
    for vieweing purposes and should never be used for enrolment or 
    verification.
    \param[in] image
    The source image.
    \param[in] size_X
    Target image widht in pixels.
    \param[in] size_Y
    Target image height in pixels.
    \param[in] stride_X
    Allocated bytes per image row. This value is always larger or equal to 
    size_X. 
    \param[out] image_data
    Array of data containing the newly constructed image. This data needs to 
    be freed with pb_free() when it is no longer needed.
    \param[out] image_size
    The length of the newly allocated array of image data. 
    \retval 
    #PB_EOK if successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    \note 
    When constructing images for display on Windows platform stride_X should 
    be equal to size_X rounded up 
    to the nearest value so that stride_X mod 4 = 0.
    */
    int PBCALL pb_get_image_for_viewing(
        const pb_image_t* image, 
        unsigned int size_X, 
        unsigned int size_Y, 
        unsigned int stride_X, 
        unsigned char** image_data, 
        unsigned int* image_size);
    /*!
    \fn int PBCALL pb_image_to_bmp_buffer(const pb_image_t *image, 
    unsigned char** bmp_image_buffer, unsigned int* buffer_length);
    \brief
    Converts a pb_image_t image to a bitmap file format buffer.
    \details
    Used to convert a pb_image_t image to an array of a 8 bit grayscale bitmap
    file format data. The function provides an array of data that the caller 
    can save on disk as an ordinary .bmp file. Conversion is lossless and the 
    resulting image do not use any kind of compression. The bitmap data needs 
    to be freed with pb_free() when it is no longer needed.
    \param[in] image
    The image to convert.
    \param[out] bmp_image_buffer
    Array of bitmap file data. 
    \param[out] buffer_length
    Length of bmp_image_buffer array. 
    \retval 
    #PB_EOK if successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    */
    int PBCALL pb_image_to_bmp_buffer(
        const pb_image_t *image, 
        unsigned char** bmp_image_buffer, 
        unsigned int* buffer_length);

    /*!
    \fn int PBCALL pb_bmp_buffer_to_image(
    const unsigned char* bmp_image_buffer, unsigned int buffer_length, 
    pb_image_t** image);
    \brief
    Converts a bitmap image data stream to a pb_image_t image. 
    \details
    Used to convert an bitmap image to a pb_image_t image. The function 
    currently only supports 8 bit grayscale bitmap file format images coded 
    with the Windows V3 40-byte header. The image data needs to be freed with 
    pb_free_image() when it is no longer needed.
    \param[in] bmp_image_buffer
    Array of bitmap file data.
    \param[in] buffer_length
    Length of bitmap buffer data.
    \param[out] image
    Pointer to pb_image_t image.
    \retval 
    #PB_EOK if successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    */
    int PBCALL pb_bmp_buffer_to_image(
        const unsigned char* bmp_image_buffer, 
        unsigned int buffer_length, 
        pb_image_t** image);

    /*!
    \fn int PBCALL pb_image_to_wsq_buffer(const pb_image_t *image, 
    unsigned char** wsq_image_buffer, unsigned int* buffer_length);
    \brief
    Converts a pb_image_t image to a wsq file format buffer.
    \details
    Used to convert a pb_image_t image to wsq buffer with file format data. 
    The function provides an array of data that the caller can save on disk 
    as an ordinary .wsq file. The wsq data needs to be freed with pb_free() 
    when it is no longer needed.
    \param[in] image
    The image to convert.
    \param[out] wsq_image_buffer
    Array of wsq file data. 
    \param[out] buffer_length
    Length of wsq_image_buffer array. 
    \retval 
    #PB_EOK if successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    */
    int PBCALL pb_image_to_wsq_buffer(
        const pb_image_t *image, 
        unsigned char** wsq_image_buffer, 
        unsigned int* buffer_length);

    /*!
    \fn int PBCALL pb_wsq_buffer_to_image(
    const unsigned char* wsq_image_buffer, unsigned int buffer_length, 
    pb_image_t** image);
    \brief
    Converts a wsq image data stream to a pb_image_t image. 
    \details
    Used to convert a wsq image to a pb_image_t image. The image data 
    needs to be freed with pb_free_image() when it is no longer needed.
    \param[in] wsq_image_buffer
    Array of wsq file data.
    \param[in] buffer_length
    Length of wsq buffer data.
    \param[out] image
    Pointer to pb_image_t image.
    \retval 
    #PB_EOK if successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    */
    int PBCALL pb_wsq_buffer_to_image(
        const unsigned char* wsq_image_buffer, 
        unsigned int buffer_length, 
        pb_image_t** image);

    /*!
    \fn int	PBCALL pb_cancelA(LPSTR reader);
    \brief
    Cancels an on-going operation.
    \details
    The cancelled operation will return with the error code PB_ECANCEL. 
    It is only the functions that have a timeout parameter that are 
    cancelable; other functions are unaffected. 
    The function returns PB_EOK even if there are no active operations.
    The function will not wait for the operation to cancel.
    An application may not assume that this call returns before the cancelled 
    function returns.
    \param[in] reader
    The reader that shall cancel it's operation.
    \retval 
    #PB_EOK if successful.
    \returns 
    Other possible return values are defined in \ref error codes.
    \note
    This function should not be called directly. Always call the macro version
    of the function; pb_cancel.   

    */
    int	PBCALL pb_cancelA(LPSTR reader);

    /*!
    \copydoc pb_cancelA
    */
    int	PBCALL pb_cancelW(LPWSTR reader);

#ifdef UNICODE
#define pb_cancel pb_cancelW
#else
#define pb_cancel pb_cancelA
#endif

#ifdef __cplusplus
}
#endif

#endif






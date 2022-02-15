/****************************************************************************
*
* verify2.c
*
*
* Description:
*  This simple console example provides the framework of the functionality
*  needed for verification of fingerprints to be used with Precise
*  Match-On-Card technology(TM). The example follows the recommended
*  procedures described in the Precise BioMatch(TM) Flex H User Manual.
*
*  During verification, a biometric header is fetched from the user's smart
*  card and a fingerprint image from one of the user's enrolled fingers is
*  captured in accordance with the requirements specified in the biometric
*  header. The image is processed to generate verification data. This
*  verification data is then sent to the user's smart card where it is
*  compared against the secure reference data on the card.
*
***************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pb_flex_h.h"

/****************************************************************************
* Defines
/***************************************************************************/
#define APDU_DATA_SIZE      240

/****************************************************************************
* Global variables
/***************************************************************************/
static SCARDCONTEXT context;

/****************************************************************************
* Prototype definitions
****************************************************************************/
static void 
print_error_reason(int ret);

static void 
callback_verify(int   token,
                void *context);

static int 
verify_template(SCARDHANDLE card_handle);

static SCARDHANDLE 
connect_to_card(void);

/****************************************************************************
* Main
****************************************************************************/
int main_verify2(void)
{
    SCARDHANDLE card_handle;
    int			ret;
    int         dummy;

    printf("MoC verification example 2\n");
    printf("--------------------------\n\n");

    /* Initialize the framework. */
    ret = pb_initialize();
    if (ret != PB_EOK)
    {
        fprintf(stderr, "INITIALIZE::");
        print_error_reason(ret);
        return PB_EFATAL;
    }

    /* Connect to the smart card */
    card_handle = connect_to_card();
    if (card_handle == SCARD_E_INVALID_HANDLE)
    {
        pb_release();
        fprintf(stderr, "Smart card error.\n");
        return PB_EFATAL;
    }

    /* Verify fingerprint template using MoC. */
    ret = verify_template(card_handle);
    
    SCardDisconnect(card_handle, SCARD_LEAVE_CARD);
    SCardReleaseContext(context);

    /* Free resources allocated by pb_initialize(). */
    pb_release();

    if (ret != PB_EOK)
    {
        print_error_reason(ret);
        scanf_s("%d", &dummy);
        return PB_EFATAL;
    }	

    if (ret != PB_EOK)
    {
        print_error_reason(ret);
        fprintf(stderr, "::RELEASE\n");
        scanf_s("%d", &dummy);     
        return PB_EFATAL;
    }

    printf("\nEnter 0 to return to main menu: \n");
    scanf_s("%d", &dummy);
    return PB_EOK;
}


/****************************************************************************
*
* Description:
*  This function provides the framework needed for verification of
*  fingerprints to be used with Precise Match-On-Card(TM) technology.
*
* Arguments:
*  session     -     [in] Session for this operation.
*
* Return value:
*  Returns PB_EOK if successful, otherwise an error code is returned.
*
***************************************************************************/
static int verify_template(SCARDHANDLE card_handle)
{
    int				ret, times, rest, i;
    char			bio_header[118];
    LONG            result;
    BYTE            send_buffer[0xFF] = {0};
    BYTE            rec_buffer[0xFF] = {0};
    DWORD           rec_len;
    pb_image_t     *image = NULL;
    unsigned char  *ver_data;
    int             ver_data_size = 0;
    BYTE            aid[] = { 0xA0, 0x00, 0x00, 0x00, 0x84, 0x00, 0x00 };
    LPBYTE          pbAttr = NULL;
    DWORD           cByte = SCARD_AUTOALLOCATE;


    /* Select the BioManagerapplet on the card. */
    send_buffer[0] = 0x00;
    send_buffer[1] = 0xA4;
    send_buffer[2] = 0x04;
    send_buffer[3] = 0x00;
    send_buffer[4] = sizeof(aid);
    memcpy(&send_buffer[5], aid, sizeof(aid));
    rec_len = sizeof(rec_buffer);

    result = SCardTransmit(card_handle, SCARD_PCI_T0, send_buffer, 
        sizeof(aid) + 5, NULL, rec_buffer, &rec_len);

    if (result != SCARD_S_SUCCESS)
    {
        fprintf(stderr, "Smart card error.\n");
        return PB_EFATAL;
    }

    /* Read the biometric header from the smart card */
    send_buffer[0] = 0xB0;
    send_buffer[1] = 0x34;
    send_buffer[2] = 0x00;
    send_buffer[3] = 0x00;
    send_buffer[4] = 0x76; /* 118, size of biometric header */
    rec_len = sizeof(rec_buffer);

    result = SCardTransmit(card_handle, SCARD_PCI_T0, send_buffer, 
        5, NULL, rec_buffer, &rec_len);

    if (result != SCARD_S_SUCCESS || 
        !(rec_buffer[rec_len-2] == 0x90 && rec_buffer[rec_len-1] == 0))
    {
        fprintf(stderr, "Smart card error.\n");
        return PB_EFATAL;
    }

    memcpy(bio_header, rec_buffer, rec_len - 2);

    /* Aquire the verification data. */
    printf("Place finger on reader.\n");

    ret = SCardGetAttrib(card_handle, 
        SCARD_ATTR_DEVICE_FRIENDLY_NAME,
        (LPBYTE)&pbAttr,
        &cByte);

    if (ret != SCARD_S_SUCCESS)
    {
        return PB_EREADER;
    }

    /* check if the smart card reader we have a handle to is a combined
       Precise Biometrics biometric & smart card reader. */
    if (strncmp("Precise Biometrics", pbAttr, 18) == 0)
    {
        /* Use smart card handle to capture image. Smart card connection is 
           made exclusive. */
        ret = pb_sc_capture_image(card_handle, 
                                  15000,
                                  &image,
                                  callback_verify,
                                  NULL);
    }
    /* if not, use the first found biometric reader to capture the 
       image for verification */
    else
    {
        int	nof_readers;
        char *reader_list = NULL;

        ret = pb_list_readers(&reader_list, &nof_readers);

        if (ret != PB_EOK)
        {
            SCardFreeMemory(context, pbAttr);
            return PB_EREADER;
        }

        ret = pb_capture_image(reader_list, 
            15000,
            &image,
            callback_verify,
            NULL);

        pb_free(reader_list);
    }

    SCardFreeMemory(context, pbAttr);
    
    if (ret != PB_EOK) 
    {
        fprintf(stderr, "Capture image error.\n");
        return PB_EFATAL;
    }

    ret = pb_fh_create_verification_data(image,
                                         bio_header,
                                         sizeof(bio_header),
                                         &ver_data,
                                         &ver_data_size);

    pb_free_image(image);

    if (ret != PB_EOK) 
    {
        fprintf(stderr, "Smart card error.\n");
        return PB_EFATAL;
    }

    printf("Matching...\n");

    times = ver_data_size / APDU_DATA_SIZE;
    rest = ver_data_size % APDU_DATA_SIZE;

    for(i = 0; i < times; i ++)
    {
        send_buffer[0] = 0xb0;
        send_buffer[1] = 0x32;
        send_buffer[2] = 0;
        if (i == 0)
        {
            /* P1 = Init */
            send_buffer[3] = 0x00;
        }
        else
        {
            /* P1 = Update */
            send_buffer[3] = 0x01;
        }
        send_buffer[4] = APDU_DATA_SIZE;

        memcpy((unsigned char*)send_buffer + 5, 
               (unsigned char*)ver_data + (i * APDU_DATA_SIZE), 
               APDU_DATA_SIZE);

        rec_len = sizeof(rec_buffer);

        result = SCardTransmit(card_handle, SCARD_PCI_T0, send_buffer, 
            APDU_DATA_SIZE + 5, NULL, rec_buffer, &rec_len);

        if (result != SCARD_S_SUCCESS || 
            !(rec_buffer[0] == 0x90 && rec_buffer[1] == 0))
        {
            pb_free(ver_data);
            fprintf(stderr, "Smart card error.\n");
            return PB_EFATAL;
        }
    }

    /* Send last part of verification data to smart card - P1 = Update */
    send_buffer[0] = 0xb0;
    send_buffer[1] = 0x32;
    send_buffer[2] = 0;
    send_buffer[3] = 0x01;
    send_buffer[4] = rest;

    memcpy((unsigned char*)send_buffer + 5, 
           (unsigned char*)ver_data + (i * APDU_DATA_SIZE), 
           rest);

    rec_len = sizeof(rec_buffer);

    result = SCardTransmit(card_handle, SCARD_PCI_T0, send_buffer, 
        rest + 5, NULL, rec_buffer, &rec_len);

    if (result != SCARD_S_SUCCESS || 
        !(rec_buffer[0] == 0x90 && rec_buffer[1] == 0))
    {
        pb_free(ver_data);
        fprintf(stderr, "Smart card error.\n");
        return PB_EFATAL;
    }

    pb_free(ver_data);

    /* Start the match - P1 = Final */
    send_buffer[0] = 0xb0;
    send_buffer[1] = 0x32;
    send_buffer[2] = 0;
    send_buffer[3] = 0x02;
    send_buffer[4] = 0x00;

    rec_len = sizeof(rec_buffer);

    result = SCardTransmit(card_handle, SCARD_PCI_T0, send_buffer, 
        5, NULL, rec_buffer, &rec_len);

    if (result != SCARD_S_SUCCESS)
    {
        fprintf(stderr, "Smart card error.\n");
        return PB_EFATAL;
    }

    /* Control the result and inform the user. */
    if ((rec_buffer[0] == 0x90) && (rec_buffer[1] == 0x00))
    {
        printf("MATCH RESULT -->   *** MATCH OK ***\n");
    }
    else
    {
        printf("MATCH RESULT -->   --- MATCH FAIL ---\n");
    }

    return PB_EOK;
}

/****************************************************************************
*
* Description:
*  Get a handle to a smart card. Only T=0 cards are supported.
*
* Arguments:
*
* Return value:
*  Returns a handle to a smart card.
*
***************************************************************************/
static SCARDHANDLE connect_to_card(void)
{
    LONG res;
    SCARD_READERSTATE reader_state;
    SCARDHANDLE card;
    LPTSTR reader, reader_list;
    DWORD reader_list_size;
    DWORD protocol;

    res = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &context);
    if (res != SCARD_S_SUCCESS)
    {
        fprintf(stderr, "No contact with reader.\n");
        return SCARD_E_INVALID_HANDLE;
    }

    res = SCardListReaders(context, NULL, NULL, &reader_list_size);
    if (res != SCARD_S_SUCCESS)
    {
        SCardReleaseContext(context);
        fprintf(stderr, "No contact with reader.\n");
        return SCARD_E_INVALID_HANDLE;
    }

    reader_list = malloc(reader_list_size);
    if (reader_list == NULL)
    {
        SCardReleaseContext(context);
        fprintf(stderr, "Not enough memory.\n");
        return SCARD_E_INVALID_HANDLE;
    }

    res = SCardListReaders(context, NULL, reader_list, &reader_list_size);
    if (res != SCARD_S_SUCCESS)
    {
        free(reader_list);
        SCardReleaseContext(context);
        fprintf(stderr, "No contact with reader.\n");
        return SCARD_E_INVALID_HANDLE;
    }

    reader = reader_list;

    reader_state.szReader = malloc(strlen(reader) + 1);
    if (reader_state.szReader == NULL)
    {
        free(reader_list);
        SCardReleaseContext(context);
        fprintf(stderr, "No contact with reader.\n");
        return SCARD_E_INVALID_HANDLE;
    }

    strcpy_s((char*)reader_state.szReader, strlen(reader) + 1, reader);
    reader_state.dwCurrentState	= SCARD_STATE_UNAWARE;

    free(reader_list);

    res = SCardGetStatusChange(context, 0, &reader_state, 1);
    if (res != SCARD_S_SUCCESS)
    {
        free((void*)reader_state.szReader);
        SCardReleaseContext(context);
        fprintf(stderr, "No contact with reader.\n");
        return SCARD_E_INVALID_HANDLE;
    }

    if (!(reader_state.dwEventState & SCARD_STATE_PRESENT))
    {
        free((void*)reader_state.szReader);
        SCardReleaseContext(context);
        fprintf(stderr, "Please insert a card.\n");
        return SCARD_E_INVALID_HANDLE;
    }

    /* Do exclusive connection since we will do multiple calls to the smart card */
    /* and want full control of the smart card during this interaction. */
    res = SCardConnect(context, reader_state.szReader, SCARD_SHARE_EXCLUSIVE,
        SCARD_PROTOCOL_T0, &card, &protocol);
    free((void*)reader_state.szReader);
    if (res != SCARD_S_SUCCESS)
    {
        SCardReleaseContext(context);
        fprintf(stderr, "No contact with reader.\n");
        return SCARD_E_INVALID_HANDLE;
    }

    return card;
}

/****************************************************************************
*
* Description:
*  This callback is called during 'pb_capture_verification_data()'.
*
* Arguments:
*  session      - [in] Session for this operation.
*  image		- [out] The image that was used to create templates.
*  context		- [in/out] Pointer to user defined data.
*
* Return value:
*  None
*
***************************************************************************/
static void callback_verify(int   token,
                            void *context)
{
    int		    ret;
    int		    present;
    int		    finger_condition;
    pb_image_t *image;


    /* Check if there is a fingerprint present in the image. */
    ret = pb_cb_finger_status(token, &image, NULL, 
                              &finger_condition, &present);

    if (ret != PB_EOK)
    {
        print_error_reason(ret);
        fprintf(stderr, "::FINGER_PRESENT\n");

        /* Cancel current operation. */
        pb_cb_cancel(token);
        return;
    }

    if (!present)
    {
        printf("Please place finger on sensor.\n");
        return;
    }

    if ((finger_condition != PB_STATUS_OK) &&
        (finger_condition != PB_STATUS_UNKNOWN))
    {
        if (finger_condition == PB_STATUS_TOO_WET)
            printf("Ease the pressure on the sensor and/or wipe your finger on a piece of cloth\n");
        if (finger_condition == PB_STATUS_TOO_DRY)
            printf("Press a little harder on the sensor and/or breathe on your finger\n");

        return;
    }
}

/****************************************************************************
*
* Description:
*  Print information regarding the error code returned by the framework.
*
* Arguments:
*  ret     - [in] Error code returned by the framework.
*
* Return value:
*  None
*
***************************************************************************/
static void print_error_reason(int ret)
{
    switch(ret)
    {
    case PB_EBUFFER:
        fprintf(stderr, "ERROR::INCORRECT BUFFER SIZE\n");
        return;

    case PB_ECANCEL:
        fprintf(stderr, "ERROR::CANCELED BY CALLER");
        return;

    case PB_EFATAL:
        fprintf(stderr, "ERROR::UNSPECIFIED FATAL ERROR\n");
        return;

    case PB_EBIR:
        fprintf(stderr, "ERROR::UNRECOGNIZED/CORRUPT BIR\n");
        return;

    case PB_EDATA:
        fprintf(stderr, "ERROR::WRONG FORMAT OF DATA\n");
        return;

    case PB_EREADER:
        fprintf(stderr, "ERROR::WRONG READER HANDLE\n");
        return;

    case PB_EMEMORY:
        fprintf(stderr, "ERROR::CANNOT ALLOCATE MEMORY\n");
        return;

    case PB_EINIT:
        fprintf(stderr, "ERROR::INTERFACE NOT INITIALIZED\n");
        return;

    case PB_ESUPPORT:
        fprintf(stderr, "ERROR::OPERATION NOT SUPPORTED\n");
        return;

    case PB_EPARAMETER:
        fprintf(stderr, "ERROR::INVALID PARAMETERS\n");
        return;

    case PB_ETIMEOUT:
        fprintf(stderr, "ERROR::TIMEOUT\n");
        return;

    default:
        fprintf(stderr, "ERROR::UNKNOWN ERROR CODE: %d\n", ret);
        return;
    }
}

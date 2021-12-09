#include <windows.h>
#include <winhttp.h>
#include "bofdefs.h"
#include "base.c"


void get_certificate(const char * url, int port) {
    HMODULE winhttp = LoadLibrary("winhttp");
    if(winhttp == NULL) {internal_printf("Unable to load required library\n"); return;}

    

    char useragent[] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36 Edg/86.0.622.51";

    wchar_t *hostname = Utf8ToUtf16(url);


    HINTERNET hSession = WINHTTP$WinHttpOpen(
                                (LPCWSTR)useragent, 
                                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, 
                                WINHTTP_NO_PROXY_BYPASS, 
                                WINHTTP_NO_PROXY_BYPASS, 
                                0
                        );
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;

    WINHTTP_CERTIFICATE_INFO hCertInfo;
    DWORD dwSizeCertInfo = sizeof(WINHTTP_CERTIFICATE_INFO);

    if (hSession)
    {
        hConnect = WINHTTP$WinHttpConnect(hSession, (LPCWSTR)hostname, port, 0);
    }
    else
    {
        internal_printf("[!] Error in WinHttpConnect");
    }

    if (hConnect)
    {
        hRequest = WINHTTP$WinHttpOpenRequest(hConnect, L"GET", L"/",
                                                NULL, WINHTTP_NO_REFERER, 
                                                WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                                WINHTTP_FLAG_SECURE
                                            );
        if (hRequest)
        {
            if(WINHTTP$WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
            {

                if(WINHTTP$WinHttpQueryOption(hRequest, WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT, &hCertInfo, &dwSizeCertInfo))
                {
                    internal_printf("Certificate issuer: \n----\n%ls\n----", hCertInfo.lpszIssuerInfo);
                    KERNEL32$LocalFree(hCertInfo.lpszIssuerInfo);
                    KERNEL32$LocalFree(hCertInfo.lpszSubjectInfo);
                } else { 
                    internal_printf("[!] Error in WinHttpQueryOption\n");
                }
            }
        }
        else
        {
            internal_printf("[!] Error in OpenRequest\n");
        }
    }

    WINHTTP$WinHttpCloseHandle(hConnect);
    WINHTTP$WinHttpCloseHandle(hRequest);	
}

#ifdef BOF
VOID go( 
    IN PCHAR Buffer, 
    IN ULONG Length
) 
{
    datap parser;
    char * hostname;
    ULONG port;

    BeaconDataParse(&parser, Buffer, Length);
    hostname = BeaconDataExtract(&parser, NULL);
    port = BeaconDataInt(&parser);

    port = port == 0 ? 443 : port;

    if(!bofstart())
    {
        return;
    }
    get_certificate(hostname, port);
    printoutput(TRUE);
};

#else

int main()
{
    get_certificate("www.google.com", 443);
}

#endif

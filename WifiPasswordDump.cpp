#include <Windows.h>
#include <Wlanapi.h>
#include <stdio.h>
#include <assert.h>
#include <string>
#include <regex>
#include <iostream>

#pragma comment(lib, "wlanapi.lib")


int main()
{
    HANDLE hClient;
    DWORD negotiatedVersion = 2;
    WlanOpenHandle(negotiatedVersion, nullptr, &negotiatedVersion, &hClient);
    if (GetLastError() != ERROR_SUCCESS) {
        negotiatedVersion = 1;
        WlanOpenHandle(negotiatedVersion, nullptr, &negotiatedVersion, &hClient);
        if (GetLastError() != ERROR_SUCCESS) {
            printf("Couldnot negotiaite client version\n");
        }
    }
    else {
        assert(hClient);
        printf("Negotiated Version: %d\n",negotiatedVersion);
    }

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    PWLAN_INTERFACE_INFO pIfInfo = NULL;

    if (WlanEnumInterfaces(hClient, nullptr, &pIfList) != ERROR_SUCCESS) {
        printf("Couldnot enumerate interfaces\n");
    }


    DWORD dwResult = 0;
    int iRet = 0;

    WCHAR GuidString[40] = { 0 };

    // Enumerate Interfaces
    for (int i = 0; i < (int)pIfList->dwNumberOfItems; i++) {
        pIfInfo = (WLAN_INTERFACE_INFO*)&pIfList->InterfaceInfo[i];
        wprintf(L"  Interface Index[%d]: %lu\n", i, i);
        iRet = StringFromGUID2(pIfInfo->InterfaceGuid, (LPOLESTR)&GuidString, 39);
        GUID& guid = pIfInfo->InterfaceGuid;
        if (iRet == 0)
            wprintf(L"StringFromGUID2 failed\n");
        else {
            wprintf(L"  InterfaceGUID[%d]: %ws\n", i, GuidString);
        }
        wprintf(L"  Interface Description[%d]: %ws\n", i, pIfInfo->strInterfaceDescription);



        // Enumerate Profile Lists
        PWLAN_PROFILE_INFO_LIST pProfileList = NULL;
        PWLAN_PROFILE_INFO pProfile = NULL;
    
        DWORD result = WlanGetProfileList(hClient, &guid, nullptr, &pProfileList);
        if(result != ERROR_SUCCESS)  
            wprintf(L"WlanGetProfileList failed with error: %u\n",dwResult);

        wprintf(L"  Num Entries: %lu\n\n", pProfileList->dwNumberOfItems);
        wprintf(L"SSID:PASSWORD\n");
        wprintf(L"-------------\n");
        for (int j = 0; j < pProfileList->dwNumberOfItems; j++) {
            pProfile = (WLAN_PROFILE_INFO*)&pProfileList->ProfileInfo[j];
            auto& profileName = pProfile->strProfileName;

            //Extract Passwords
            DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
            DWORD access = WLAN_READ_ACCESS;

            LPWSTR pProfileXml = nullptr;
            DWORD result = WlanGetProfile(hClient, &guid, profileName, nullptr, &pProfileXml, &flags , &access );

            if (result == ERROR_SUCCESS) {
                // parse password from xml
               std::wstring xml = std::wstring(pProfileXml);
               
               std::wstring startTag = L"<keyMaterial>";
               std::wstring endTag = L"</keyMaterial>";

               int startIndex = xml.find(startTag) + 13;;
               int endIndex = xml.find(endTag);
               int range = endIndex - startIndex;
               
               if (startIndex == std::string::npos || endIndex == std::string::npos) continue;
               
               wprintf(L"%ws:", profileName);

               // Extract Clear Text password from xml
               std::wstring password = xml.substr(startIndex, range);

                wprintf(L"%ws", password.c_str());
                   if (pProfileXml) {
                    WlanFreeMemory(pProfileXml);
                    pProfileXml = nullptr;
                }
            }
            else {
                LPWSTR text;
                DWORD chars = ::FormatMessage(
                    FORMAT_MESSAGE_ALLOCATE_BUFFER | // function allocates
                    FORMAT_MESSAGE_FROM_SYSTEM |
                    FORMAT_MESSAGE_IGNORE_INSERTS,
                    nullptr, result, 0,
                    (LPWSTR)&text, // ugly cast
                    0, nullptr);

                wprintf(L"Error: %ws", text);
                ::LocalFree(text);

            }
            wprintf(L"\n");
            
        }


}

    printf("\n\nPress any key to exit\n\n");
    getchar();
    // Cleanup
    WlanFreeMemory(pIfList);
    pIfList = NULL;


   
}


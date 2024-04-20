// HARDSN_GetTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define _WIN32_DCOM
#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>

#include <vector>
#include <string>

#pragma comment(lib, "wbemuuid.lib")

enum class WmiQueryError {
    None,
    BadQueryFailure,
    PropertyExtractionFailure,
    ComInitializationFailure,
    SecurityInitializationFailure,
    IWbemLocatorFailure,
    IWbemServiceConnectionFailure,
    BlanketProxySetFailure,
};

struct WmiQueryResult
{
    std::vector<std::wstring> ResultList;
    WmiQueryError Error = WmiQueryError::None;
    std::wstring ErrorDescription;
};

WmiQueryResult getWmiQueryResult(std::wstring wmiQuery, std::wstring propNameOfResultObject, bool allowEmptyItems = false) {

    WmiQueryResult retVal;
    retVal.Error = WmiQueryError::None;
    retVal.ErrorDescription = L"";

    HRESULT hres;


    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    IEnumWbemClassObject* pEnumerator = NULL;
    IWbemClassObject* pclsObj = NULL;
    VARIANT vtProp;


    // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        retVal.Error = WmiQueryError::ComInitializationFailure;
        retVal.ErrorDescription = L"Failed to initialize COM library. Error code : " + std::to_wstring(hres);
    }
    else
    {
        // Step 2: --------------------------------------------------
        // Set general COM security levels --------------------------
        // note: JUCE Framework users should comment this call out,
        // as this does not need to be initialized to run the query.
        // see https://social.msdn.microsoft.com/Forums/en-US/48b5626a-0f0f-4321-aecd-17871c7fa283/unable-to-call-coinitializesecurity?forum=windowscompatibility 
        hres = CoInitializeSecurity(
            NULL,
            -1,                          // COM authentication
            NULL,                        // Authentication services
            NULL,                        // Reserved
            RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
            RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
            NULL,                        // Authentication info
            EOAC_NONE,                   // Additional capabilities 
            NULL                         // Reserved
        );


        if (FAILED(hres))
        {
            retVal.Error = WmiQueryError::SecurityInitializationFailure;
            retVal.ErrorDescription = L"Failed to initialize security. Error code : " + std::to_wstring(hres);
        }
        else
        {
            // Step 3: ---------------------------------------------------
            // Obtain the initial locator to WMI -------------------------
            pLoc = NULL;

            hres = CoCreateInstance(
                CLSID_WbemLocator,
                0,
                CLSCTX_INPROC_SERVER,
                IID_IWbemLocator, (LPVOID*)&pLoc);

            if (FAILED(hres))
            {
                retVal.Error = WmiQueryError::IWbemLocatorFailure;
                retVal.ErrorDescription = L"Failed to create IWbemLocator object. Error code : " + std::to_wstring(hres);
            }
            else
            {
                // Step 4: -----------------------------------------------------
                // Connect to WMI through the IWbemLocator::ConnectServer method

                pSvc = NULL;

                // Connect to the root\cimv2 namespace with
                // the current user and obtain pointer pSvc
                // to make IWbemServices calls.
                hres = pLoc->ConnectServer(
                    _bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
                    NULL,                    // User name. NULL = current user
                    NULL,                    // User password. NULL = current
                    0,                       // Locale. NULL indicates current
                    NULL,                    // Security flags.
                    0,                       // Authority (for example, Kerberos)
                    0,                       // Context object 
                    &pSvc                    // pointer to IWbemServices proxy
                );

                // Connected to ROOT\\CIMV2 WMI namespace

                if (FAILED(hres))
                {
                    retVal.Error = WmiQueryError::IWbemServiceConnectionFailure;
                    retVal.ErrorDescription = L"Could not connect to Wbem service.. Error code : " + std::to_wstring(hres);
                }
                else
                {
                    // Step 5: --------------------------------------------------
                    // Set security levels on the proxy -------------------------

                    hres = CoSetProxyBlanket(
                        pSvc,                        // Indicates the proxy to set
                        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
                        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
                        NULL,                        // Server principal name 
                        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
                        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
                        NULL,                        // client identity
                        EOAC_NONE                    // proxy capabilities 
                    );

                    if (FAILED(hres))
                    {
                        retVal.Error = WmiQueryError::BlanketProxySetFailure;
                        retVal.ErrorDescription = L"Could not set proxy blanket. Error code : " + std::to_wstring(hres);
                    }
                    else
                    {
                        // Step 6: --------------------------------------------------
                        // Use the IWbemServices pointer to make requests of WMI ----

                        // For example, get the name of the operating system
                        pEnumerator = NULL;
                        hres = pSvc->ExecQuery(
                            bstr_t("WQL"),
                            bstr_t(wmiQuery.c_str()),
                            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                            NULL,
                            &pEnumerator);

                        if (FAILED(hres))
                        {
                            retVal.Error = WmiQueryError::BadQueryFailure;
                            retVal.ErrorDescription = L"Bad query. Error code : " + std::to_wstring(hres);
                        }
                        else
                        {
                            // Step 7: -------------------------------------------------
                            // Get the data from the query in step 6 -------------------

                            pclsObj = NULL;
                            ULONG uReturn = 0;

                            while (pEnumerator)
                            {
                                HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
                                    &pclsObj, &uReturn);

                                if (0 == uReturn)
                                {
                                    break;
                                }

                                // VARIANT vtProp;

                                // Get the value of desired property
                                hr = pclsObj->Get(propNameOfResultObject.c_str(), 0, &vtProp, 0, 0);
                                if (S_OK != hr) {
                                    retVal.Error = WmiQueryError::PropertyExtractionFailure;
                                    retVal.ErrorDescription = L"Couldn't extract property: " + propNameOfResultObject + L" from result of query. Error code : " + std::to_wstring(hr);
                                }
                                else {
                                    BSTR val = vtProp.bstrVal;

                                    // Sometimes val might be NULL even when result is S_OK
                                    // Convert NULL to empty string (otherwise "std::wstring(val)" would throw exception)
                                    if (NULL == val) {
                                        if (allowEmptyItems) {
                                            retVal.ResultList.push_back(std::wstring(L""));
                                        }
                                    }
                                    else {
                                        retVal.ResultList.push_back(std::wstring(val));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Cleanup
    // ========

    VariantClear(&vtProp);
    if (pclsObj)
        pclsObj->Release();

    if (pSvc)
        pSvc->Release();

    if (pLoc)
        pLoc->Release();

    if (pEnumerator)
        pEnumerator->Release();

    CoUninitialize();

    return retVal;
}

void queryAndPrintResult(std::wstring query, std::wstring propNameOfResultObject)
{
    WmiQueryResult res;
    res = getWmiQueryResult(query, propNameOfResultObject);

    if (res.Error != WmiQueryError::None) {
        std::wcout << "Got this error while executing query: " << std::endl;
        std::wcout << res.ErrorDescription << std::endl;
        return; // Exitting function
    }

    for (const auto& item : res.ResultList) {
        std::wcout << item << std::endl;
    }
}

int main(int argc, char** argv)
{

    // Get OS and partition
    // queryAndPrintResult(L"SELECT * FROM Win32_OperatingSystem", L"Name");

    // Get list of running processes
    // queryAndPrintResult(L"Select * From Win32_Process", L"Name");

    // Get serial number of Hard Drive
    queryAndPrintResult(L"SELECT SerialNumber FROM Win32_PhysicalMedia", L"SerialNumber");

    system("pause");
}
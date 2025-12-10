#include <libhat/scanner.hpp>
#include <libhat/signature.hpp>
#include "utils/detour.hpp"

// bool TrialManager::isTrial()
std::unique_ptr<detour> gIsTrialDetour = nullptr;
hat::fixed_signature gIsTrialSig = hat::compile_signature<"40 53 48 83 ec ? 48 8b 05 ? ? ? ? 48 33 c4 48 89 44 24 ? 48 8b d9 48 8b 49 ? 48 8b 01 48 8b 80 ? ? ? ? ff 15 ? ? ? ? 48 8b c8">();

static bool isTrial(void* _this)
{
    return false;
}

BOOL WINAPI DllMain(HMODULE /* module */, DWORD reason,  LPVOID /* reserved */)
{
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
        {
            MH_Initialize();
            hat::scan_result isTrialAddr = hat::find_pattern(gIsTrialSig, ".text");
            gIsTrialDetour = std::make_unique<detour>(isTrialAddr.get(), &isTrial);
            gIsTrialDetour->enable();

            break;
        }
        case DLL_PROCESS_DETACH:
        {
            gIsTrialDetour->disable();
            gIsTrialDetour.reset();
            MH_Uninitialize();

            break;
        }

        default: break;
    }

    return TRUE;
}

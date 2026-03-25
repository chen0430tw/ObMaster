#include "patch_store.h"

std::vector<PatchRecord> g_patches;

PatchRecord* FindPatch(DWORD64 addr) {
    for (auto& p : g_patches) {
        if (p.addr == addr) return &p;
        if (addr >= p.page_start && addr < p.page_start + 4096) return &p;
    }
    return nullptr;
}

void FreePatchShadow(PatchRecord& rec) {
    if (!rec.has_shadow || !rec.shadow_va) return;
    VirtualUnlock(rec.shadow_va, 4096);
    VirtualFree(rec.shadow_va, 0, MEM_RELEASE);
    rec.shadow_va  = nullptr;
    rec.has_shadow = false;
    rec.shadow_pa  = 0;
}

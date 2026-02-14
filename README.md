# hooking

Function hooking in rust
-----


Each function creates a stub in memory that consists of

| Section | Description |
| ------| ------|
| Original fn detour stub address | A function pointer the generated detour stub to call the original function |
| Hooking stub | A small stub that adds some metadata (like adding detour stub address to r10 reg) before calling the hook |
| Original fn detour stub | stub that re-creates the orignal fn call instructions lost to hook, then calls the hooked function |

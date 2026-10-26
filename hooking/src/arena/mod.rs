//! Arenas hold the code generated for hooks: trampolines and relocated
//! instructions. Placing code in an arena must never change the protection
//! of code that may already be running.

use std::fmt::Debug;
use std::ptr::NonNull;

use crate::error::Result;

mod dual;
mod sealed;

pub use dual::DualMappedArena;
pub use sealed::SealedArena;

pub type DefaultArena = DualMappedArena;

/// Assembles code to run at the given address.
pub type Assemble<'a> = dyn FnMut(usize) -> Result<Vec<u8>> + 'a;

pub trait CodeArena: Debug + Send + Sync {
    /// Place code in the arena, preferably within rel32 range of `near`, and
    /// return the address it was placed at.
    ///
    /// Generated code depends on the address it runs at, so `assemble` is
    /// given the address its code will be placed at. If the code doesn't fit
    /// there, `assemble` is called again with a new address.
    fn place(&self, near: Option<usize>, assemble: &mut Assemble) -> Result<NonNull<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::HookingError;
    use crate::mem::Protection;
    use crate::sys;

    // mov eax, 42; ret
    const RETURN_42: &[u8] = &[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];

    /// Place `RETURN_42`, check it runs, and return where it was placed.
    fn place_and_call(arena: &dyn CodeArena) -> usize {
        let code = arena.place(None, &mut |_| Ok(RETURN_42.to_vec())).unwrap();
        let f: extern "C" fn() -> u32 = unsafe { std::mem::transmute(code.as_ptr()) };
        assert_eq!(f(), 42);
        code.as_ptr() as usize
    }

    /// Place `RETURN_42` padded to `len` bytes. Returns every address
    /// `assemble` was given, and where the code was placed.
    fn place_padded(arena: &dyn CodeArena, len: usize) -> (Vec<usize>, usize) {
        let mut offered = Vec::new();
        let placed = arena
            .place(None, &mut |at| {
                offered.push(at);
                let mut code = RETURN_42.to_vec();
                code.resize(len, 0x90);
                Ok(code)
            })
            .unwrap();
        (offered, placed.as_ptr() as usize)
    }

    fn protection_at(addr: usize) -> Protection {
        sys::query_protection(NonNull::new(addr as *mut u8).unwrap()).unwrap()
    }

    fn assert_places_near(arena: &dyn CodeArena) {
        let near = assert_places_near as fn(&dyn CodeArena) as usize;
        let placed = arena
            .place(Some(near), &mut |_| Ok(RETURN_42.to_vec()))
            .unwrap();
        assert!(sys::in_rel32_range(near, placed.as_ptr() as usize));
    }

    #[test]
    fn dual_mapped_shares_chunks() {
        let arena = DualMappedArena::new();
        let first = place_and_call(&arena);
        let second = place_and_call(&arena);
        assert_eq!(second, first + RETURN_42.len());
    }

    #[test]
    fn dual_mapped_is_never_writable() {
        let arena = DualMappedArena::new();
        assert_eq!(
            protection_at(place_and_call(&arena)),
            Protection::ReadExecute
        );
    }

    #[test]
    fn dual_mapped_retries_when_full() {
        let arena = DualMappedArena::new();
        let first = place_and_call(&arena);

        let (offered, placed) = place_padded(&arena, dual::CHUNK_SIZE + 1);
        assert_eq!(offered.len(), 2, "should retry in a new chunk");
        assert_eq!(offered[0], first + RETURN_42.len());
        assert_eq!(offered[1], placed);
    }

    #[test]
    fn sealed_uses_fresh_executable_pages() {
        let arena = SealedArena::new();
        let first = place_and_call(&arena);
        let second = place_and_call(&arena);
        let page_size = sys::page_size();
        assert_ne!(
            sys::align_down(first, page_size),
            sys::align_down(second, page_size)
        );
        assert_eq!(protection_at(first), Protection::ReadExecute);
    }

    #[test]
    fn sealed_retries_with_more_pages() {
        let arena = SealedArena::new();
        let (offered, placed) = place_padded(&arena, sys::page_size() + 1);
        assert_eq!(offered.len(), 2, "should retry with more pages");
        assert_eq!(offered[1], placed);
    }

    #[test]
    fn arenas_place_near() {
        assert_places_near(&DualMappedArena::new());
        assert_places_near(&SealedArena::new());
    }

    #[test]
    fn assemble_errors_are_returned() {
        for arena in [
            &DualMappedArena::new() as &dyn CodeArena,
            &SealedArena::new(),
        ] {
            let result = arena.place(None, &mut |_| Err(HookingError::NotHooked));
            assert!(matches!(result, Err(HookingError::NotHooked)));
        }
    }
}

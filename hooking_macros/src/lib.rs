use std::ffi::CString;

// lib.rs of proc macro crate
use darling::FromMeta;
use proc_macro::TokenStream;
use proc_macro2::Literal;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

#[derive(FromMeta)]
#[darling(derive_syn_parse)]
struct HookArgs {
    lib: Option<String>,
    method: String,
}

#[proc_macro_attribute]
pub fn hook(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args: HookArgs = match syn::parse(attr) {
        Ok(v) => v,
        Err(e) => {
            return e.to_compile_error().into();
        }
    };

    let func = parse_macro_input!(item as ItemFn);
    let vis = &func.vis;

    let func_name = &func.sig.ident;
    let ctor_name = quote::format_ident!("__hook_register_{}", func_name);

    let target_method = Literal::c_string(&CString::new(args.method).unwrap());
    let target_lib = if let Some(lib) = args.lib {
        let lib = Literal::c_string(&CString::new(lib).unwrap());
        quote! { Some(#lib) }
    } else {
        quote! { None }
    };

    let macro_out = quote! {
        #func

        #vis mod #func_name {
            use ::hooking::error::Result;
            use ::hooking::__macro_support;

            static __HOOK: __macro_support::StaticHook = __macro_support::StaticHook::new();

            pub unsafe fn enable_hook() -> Result<()> {
                unsafe {__macro_support::enable_hook(&__HOOK) }
            }

            pub unsafe fn disable_hook() -> Result<()> {
                unsafe { __macro_support::disable_hook(&__HOOK) }
            }

            pub fn get_hook() -> Result<__macro_support::StaticHookGuard> {
                unsafe { __macro_support::get_hook(&__HOOK) }
            }


            #[::ctor::ctor(unsafe)]
            fn #ctor_name() {
                let ptr = super::#func_name as *mut u8;

                unsafe { ::hooking::__macro_support::init_hook(&__HOOK, #target_lib, #target_method, ptr) };
            }
        }


    };

    macro_out.into()
}

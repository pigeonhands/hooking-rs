use std::ffi::CString;

// lib.rs of proc macro crate
use darling::FromMeta;
use proc_macro::TokenStream;
use proc_macro2::Literal;
use quote::quote;
use syn::{ItemFn, LitStr, parse_macro_input};

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

    let func_name = &func.sig.ident;
    let ctor_name = quote::format_ident!("__hook_register_{}", func_name);

    let target_method = Literal::c_string(&CString::new(args.method).unwrap());
    let target_lib = if let Some(lib) = args.lib {
        let lib = Literal::c_string(&CString::new(lib).unwrap());
        quote! { Some(#lib) }
    } else {
        quote! { None }
    };

    quote! {
        #func

        #[::ctor::ctor(unsafe)]
        fn #ctor_name() {
            let ptr = #func_name as *mut u8;

            ::hooking::__macro_support::create_hook(#target_lib, #target_method, ptr);
        }
    }
    .into()
}

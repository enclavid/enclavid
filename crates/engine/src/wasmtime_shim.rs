//! Thin shim over `wasmtime` that replaces `component::Linker` /
//! `component::LinkerInstance` with wrappers injecting intercept/replay logic
//! around every host function registration.
//!
//! Wiring: `bindgen!` gets `wasmtime_crate: crate::wasmtime_shim`, so all
//! paths in generated code (e.g. `{wt}::component::Linker::instance(...)`,
//! `{wt}::component::LinkerInstance::func_wrap_async(...)`) resolve here.
//!
//! Access to the intercept state is parameterized via an accessor function
//! stored in `Linker` at construction time. This avoids requiring `T: SomeTrait`
//! bounds on wasmtime-generic `add_to_linker<T>` code, which would fail to
//! compile from bindgen output.
//!
//! Everything else (types, `__internal`, Engine/Store) is re-exported verbatim.

pub use wasmtime::*;

pub mod component {
    //! Mirror of `wasmtime::component` with Linker/LinkerInstance replaced.

    pub use wasmtime::component::*;

    use std::future::Future;
    use std::sync::Arc;

    use wasmtime::AsContextMut;

    use crate::replay::{hash_args, CallResponse, CallRequest, Replay};

    /// Accessor giving the shim access to the replay machinery from Store
    /// data. A bare function pointer — `Copy`, no hidden `T: 'static` bound.
    type StateGetter<T> = fn(&mut T) -> &mut Replay;

    /// Wraps `wasmtime::component::Linker`. Construction requires an accessor
    /// function exposing intercept state from Store data; methods otherwise
    /// mirror `wasmtime::component::Linker`.
    pub struct Linker<T: 'static> {
        inner: wasmtime::component::Linker<T>,
        state_getter: StateGetter<T>,
    }

    impl<T> Linker<T> {
        pub fn new(engine: &wasmtime::Engine, state_getter: StateGetter<T>) -> Self
        where
            T: 'static,
        {
            Self {
                inner: wasmtime::component::Linker::new(engine),
                state_getter,
            }
        }

        pub fn root(&mut self) -> LinkerInstance<'_, T> {
            LinkerInstance {
                inner: self.inner.root(),
                interface: String::new(),
                state_getter: self.state_getter,
            }
        }

        pub fn instance(&mut self, name: &str) -> wasmtime::Result<LinkerInstance<'_, T>> {
            Ok(LinkerInstance {
                inner: self.inner.instance(name)?,
                interface: name.to_string(),
                state_getter: self.state_getter,
            })
        }

        pub fn instantiate_pre(
            &self,
            component: &wasmtime::component::Component,
        ) -> wasmtime::Result<wasmtime::component::InstancePre<T>> {
            self.inner.instantiate_pre(component)
        }

        pub fn into_inner(self) -> wasmtime::component::Linker<T> {
            self.inner
        }

        pub fn inner(&self) -> &wasmtime::component::Linker<T> {
            &self.inner
        }

        pub fn inner_mut(&mut self) -> &mut wasmtime::component::Linker<T> {
            &mut self.inner
        }
    }

    /// Wraps `wasmtime::component::LinkerInstance`, injecting intercept/replay
    /// around every `func_wrap_async` registration.
    pub struct LinkerInstance<'a, T: 'static> {
        inner: wasmtime::component::LinkerInstance<'a, T>,
        interface: String,
        state_getter: StateGetter<T>,
    }

    impl<'a, T> LinkerInstance<'a, T> {
        pub fn func_wrap_async<Params, Return, F>(
            &mut self,
            name: &str,
            user_f: F,
        ) -> wasmtime::Result<()>
        where
            T: Send + 'static,
            F: Fn(
                    wasmtime::StoreContextMut<'_, T>,
                    Params,
                )
                    -> Box<dyn Future<Output = wasmtime::Result<Return>> + Send + '_>
                + Send
                + Sync
                + 'static,
            Params: ComponentNamedList + Lift + serde::Serialize + Send + 'static,
            Return: ComponentNamedList
                + Lower
                + serde::Serialize
                + serde::de::DeserializeOwned
                + Send
                + 'static,
        {
            let fq: Arc<str> = if self.interface.is_empty() {
                name.to_string().into()
            } else {
                format!("{}#{}", self.interface, name).into()
            };
            let user_f = Arc::new(user_f);
            let state_getter = self.state_getter;

            self.inner
                .func_wrap_async(name, move |mut store, params: Params| {
                    let fq = fq.clone();
                    let user_f = user_f.clone();

                    Box::new(async move {
                        let req = CallRequest {
                            fn_name: fq.to_string(),
                            args_hash: hash_args(&params)?,
                        };

                        // Phase 1: step — cached replay or mark call as live.
                        match state_getter(store.data_mut()).next::<Return>(&req)? {
                            CallResponse::Cached(r) => return Ok(r),
                            CallResponse::Live => {}
                        }

                        // Phase 2: live body — re-borrow store for user closure.
                        let inner_fut = user_f(store.as_context_mut(), params);
                        let result: wasmtime::Result<Return> = Box::into_pin(inner_fut).await;

                        // Phase 3: write response. Err propagates natively as wasm trap.
                        state_getter(store.data_mut()).write(req, &result)?;
                        result
                    })
                })
        }

        pub fn inner_mut(&mut self) -> &mut wasmtime::component::LinkerInstance<'a, T> {
            &mut self.inner
        }
    }
}

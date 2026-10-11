// QuickJS, which `componentize-qjs` builds the policy on, has no TextEncoder or
// TextDecoder, and `@enclavid/policy` keeps the state with them. The polyfill
// `fast-text-encoding` installs both, onto the global object it finds as
// `global`, which QuickJS does not define. A module of its own, so this runs
// before the polyfill does.
(globalThis as { global?: unknown }).global = globalThis;

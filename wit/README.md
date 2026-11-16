# The platform's WIT

What a policy and its plugins are built against, and what the platform serves:
`enclavid:host`, `enclavid:host-capture`, `enclavid:host-disclosure`,
`enclavid:host-icons` and `enclavid:policy`.

## Versions

A package's line is its version up to its first number that is not zero:
`0.1` for every `0.1.x`, `1` for every `1.x`. The platform's linker matches an
import by its line, so a component built against `0.1.0` runs on a platform
that serves `0.1.5`.

Within a line a version only adds: interfaces, types, functions, resource
methods. An item once released keeps its shape — its name, a function's
parameters and results, a record's fields, an enum's or a variant's cases —
since components built against it rely on that shape, and the Component Model
matches records, enums and variants exactly. Changing one starts a new line.
Doc comments may change at any time.

Every item says which version it is there since, as WASI's do:

```wit
@since(version = 0.1.3)
frames-count: func() -> u32;
```

and its package takes that version in the same change. A `use` needs none: the
type it names says it where it is defined.

    cargo test -p xtask --test since

checks that every interface, type, function and resource method says it.

## Values and handles

A set of kinds only the platform interprets — icons, texts, disclosure fields
— is handed out as handles its functions mint, so a new kind is a new function
and the line goes on. A type a component reads — a guide, which a plugin checks
frames against, or an event, which a policy matches — is a value, and a new
case or field in it starts a new line.

## Support

A line is served for at least 12 months after the first release of the line
that follows it, and a package's latest two lines are always served. A
component built against an older line is refused when it is compiled, and has
to be built again.

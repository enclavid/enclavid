# create-enclavid

Start an enclavid policy from one of its templates:

```
npm create enclavid@latest my-policy
```

It asks for the template; `-- --template <name>` names it instead. `pnpm
create enclavid`, `yarn create enclavid` and `bun create enclavid` do the same.

The templates are those of the release this package is: each names the
versions of the SDK and the WIT released with it. The project gets the
template's files, its `README.md` on how to build and push it, and
`AGENTS.md` on how a policy works and how to change one.

The build runs the `enclavid` CLI, which needs to be on the path:
[installing it](https://github.com/enclavid/enclavid/tree/main/crates/cli#install).

## In this repository

`npm pack` copies the templates in `templates/typescript/` into the package
before packing, as committed: it refuses a templates tree with changes git
does not hold, so nothing that only lies beside them is published. `npm
test` builds and tests the package.

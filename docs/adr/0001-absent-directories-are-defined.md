# Absent directories are None or an empty list, never undefined

pefile leaves a `DIRECTORY_ENTRY_*` attribute undefined when the file lacks that directory, so callers guard with `hasattr`. peoxide defines every one: single-object directories (resource, TLS, load config, and the Rich header) are `None`, list directories (import, delay import, debug, base relocation, bound import, exception, security) are empty lists, and the export directory always exists. Code can then iterate without guards, and pefile code that guards with `hasattr` keeps working.

## Consequences

`hasattr(pe, "DIRECTORY_ENTRY_TLS")` is always true, so it no longer tells you whether the file has the directory. Test for `None` or an empty list instead. The README's migration guide must say so.

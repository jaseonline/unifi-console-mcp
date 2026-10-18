# Adding an entity

The pattern used for every tool in this repo.

## 1. Capture
In the console UI, open the browser developer tools (Network tab, "Preserve log"), make the change you want to support
(create, edit, delete, enable/disable), and save a **HAR** file. **Never commit it**: it contains session cookies and
tokens. Extract the relevant requests with `scripts/har_extract.py`, then scrub secrets (some settings objects hold API
keys) before sharing any excerpt.

Note for each request: method, path, request body, status code and response body. Also test the edges: delete (which
may be a POST to a batch route), partial bodies, and what the console drops or defaults.

## 2. Spec
Add the operations to `src/unifi_console_mcp/openapi.yaml` with the observed shapes, mark writes `x-destructive`, and
give the typed tool the operations in `registry.py` (`TYPED_WRITE_TOOLS`). The generic tool will then refuse them and
name your tool.

## 3. Entity module
Create `src/unifi_console_mcp/entities/<name>.py` with an `EntitySpec` (list/create/update/delete operations, id and
name fields, whole-object or changed-fields, fields to ignore, validators) and a Pydantic input model with the
friendly fields. Register it in `tools_writes.py`. Choose a tier; tier C needs `approval_note` and should have a guard
with automatic restore if a mistake could cut connectivity.

## 4. Tests
Write unit tests against an in-memory fake console that rejects bodies the real console rejected. Cover create,
update, delete and rollback, bad inputs, a stale preview, and the generic tool refusing the write. Add the tool name to
the expected-tools test.

## 5. Live check
Copy a script from `scripts/*_live_check.py`. It should create a throwaway `zz-` object that is never switched on,
change it, replay the rollback, delete it, and confirm nothing else changed. Run it without `--run` first. Record what
the console actually stored, and add anything surprising to [verified behaviours](verified-behaviours.md).

## 6. Documentation
Add a row to [write tools](write-tools.md) and a line for each new quirk. Use documentation values in examples:
MACs `02:00:00:00:00:xx`, addresses in `192.0.2.0/24` or `10.x.x.x`, domain `example.home`.

# Category dataset provenance and license records

Every record in sources/ MUST trace to an entry here. No proprietary or
unlicensed dataset may be imported (see filtering-engine category_db.py).

## seed-manual

- File: sources/seed-manual.jsonl
- Origin: hand-assigned by the KosherGuard build (Milestone 3).
- Rights: our own assignments of well-known public domains to our
  taxonomy. No third-party database content. We hold full rights.
- Scope: intentionally small seed so the pipeline, validation and
  publication path are real. NOT a complete website database; the
  categories.json _meta label must say so.

## Evaluated and NOT imported (decision record)

- UT1 blacklists (Universite Toulouse Capitole): free for non-commercial
  use; commercial use requires a paid license. KosherGuard is a
  commercial product - NOT imported.
- Shallalist: free for non-commercial use only - NOT imported.
- Commercial feeds (e.g. zvelo, Webroot BrightCloud): require contracts
  and payment. Out of scope until a purchase decision is made; no
  material new cost may be incurred without approval.

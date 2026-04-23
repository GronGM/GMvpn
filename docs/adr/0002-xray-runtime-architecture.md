# ADR 0002: Xray runtime architecture

Status: accepted

We use an Xray-first runtime model for Windows, macOS, and Android.

iOS is treated as a dedicated runtime track and must integrate through Network Extension semantics rather than assuming desktop-style process management.

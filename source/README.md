# Readable forensic C reconstructions

These are **inert semantic reconstructions** of application behavior supported by the supplied decompiler exports and independently extracted binaries. They are not recovered original source, byte-equivalent rebuilds, or complete replacements for the original C++ applications.

`WPK_readable.c` reconstructs startup, storage/configuration handling, database checks, the visible orchestration of monitoring components, x64-helper coordination, IPC naming, and the recorder lifecycle. `UNK_` worker entry points with no supplied decompiled body remain explicitly unresolved. The actual passive configuration parser validates the 4,572-byte container, reads the four-byte update counter, decodes endpoint fields, and suppresses the SMTP secret.

`WPK64_readable.c` closely reconstructs the five application-level helper routines: quit-event waiter, main gate, class registration, hidden-window creation and message dispatch. The Visual C++ runtime is summarized in comments. The original `#3763` substring test, mutex name, hidden-window behavior, resource IDs, and shutdown behavior are preserved as model semantics.

Native hooks, live input capture, screen/audio acquisition, shared-memory access, registry changes, authentication, exfiltration and process creation have no operational implementation. The programs only change local model state and print explanatory messages. Neither file links Windows APIs or contains executable payload bytes. No malware sample is included in this package.

## Build and check

```sh
cc -std=c11 -Wall -Wextra -Werror -O2 WPK_readable.c -o wpk_model
cc -std=c11 -Wall -Wextra -Werror -O2 WPK64_readable.c -o wpk64_model
./wpk_model --self-test
./wpk64_model --self-test
./wpk64_model --marker
```

The optional `./wpk_model --inspect-config /explicit/path/to/subcfg` command performs read-only inspection of a file selected by the analyst. The original configuration is not redistributed because it contains an SMTP credential. Even when inspecting the original locally, the program prints only the credential length and a redaction marker.

`source_map.csv` maps recovered addresses and supplied source line numbers to the available application-function catalog. Confidence and omitted behavior are described in the PDF. The full 280,653-line input contains extensive library and exception-unwind output; duplicating those routines would not recover the missing application worker bodies.

# Android fixtures

Real build-tool output, so the manifest decoder and the signature check are tested
against what Android tools produce rather than against bytes written by hand.

| File | Built from | How |
| :--- | :--- | :--- |
| `*.axml` | `src/<name>.xml` | copied to `AndroidManifest.xml` (aapt accepts no other name), `aapt package -M AndroidManifest.xml -I android-23/android.jar -F out.apk`, then `AndroidManifest.xml` extracted from `out.apk` (`debuggable_from_resource` also passes `-S` with `src/debuggable_from_resource.values.xml` as `res/values/`) |
| `signed.apk.bin` | `src/cleartext_false.xml` plus a placeholder `classes.dex` and `assets/config.json` | signed with `apksigner sign` (v1, v2, v3) using a throwaway key generated for this purpose; only the public certificate is in the file |
| `tampered.apk.bin` | `signed.apk.bin` | one byte of `assets/config.json` flipped after signing |

The two packages are stored with a `.bin` suffix because the repository's `.gitignore`
excludes `*.apk` (build output must not be committed); the tests copy them to a `.apk`
name in a temporary directory.

Tools: `aapt` and `apksigner` 31.0.2 from the Ubuntu 24.04 archive, `android.jar` from
`android-sdk-platform-23`. `apksigner verify` exits `0` for `signed.apk.bin` and `1` for
`tampered.apk.bin` (each copied to a `.apk` name first); `aapt dump xmltree` on each
`.axml` shows exactly the values the tests expect.
